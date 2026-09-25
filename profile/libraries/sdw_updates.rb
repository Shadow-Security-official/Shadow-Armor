# frozen_string_literal: true

require 'date'

# Patch state, read-only: nothing is refreshed or installed by the audit.
#   pending_security   -> security updates the local package metadata knows about
#   metadata_age_days  -> how stale that metadata is (a fresh cache makes the above meaningful)
#   runtime_kernel / persistent_kernel -> running kernel vs the newest installed one
class ::SdwUpdates < Inspec.resource(1)
  name 'sdw_updates'
  desc 'Pending security updates, metadata freshness, reboot and restart debt.'
  example "describe sdw_updates do\n  its('pending_security') { should be_empty }\nend"

  include SdwHelpers

  def family
    SdwMemo.fetch(:upd_family) do
      if which('apt-get') then :apt
      elsif which('dnf') then :dnf
      elsif which('yum') then :yum
      elsif which('zypper') then :zypper
      end
    end
  end

  def pending_security
    SdwMemo.fetch(:pending_security) do
      case family
      when :apt
        out = sh('LANG=C apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null').stdout.to_s
        out.lines.select { |l| l.start_with?('Inst ') && l =~ /-security|Debian-Security/i }.map { |l| l.split[1] }.uniq
      when :dnf, :yum
        r = sh("#{family} -C -q updateinfo list --security --available 2>&1")
        if r.exit_status != 0 && r.stdout !~ /\A\s*\z/
          raise ::Inspec::Exceptions::ResourceFailed, "no usable local #{family} metadata cache (#{r.stdout.lines.first.to_s.strip}); the audit never refreshes it: run `#{family} makecache` first"
        end

        r.stdout.lines.map(&:split).select { |f| f.size >= 3 && f[0] =~ /\A[A-Z]+-\d/ }.map { |f| f[2] }.uniq
      when :zypper
        out = sh('zypper -n --no-refresh list-patches --category security 2>/dev/null').stdout.to_s
        out.lines.select { |l| l =~ /\|\s*security\s*\|/ && l =~ /needed/ }.map { |l| l.split('|')[1].to_s.strip }
      else
        raise ::Inspec::Exceptions::ResourceSkipped, 'no supported package manager'
      end
    end
  end

  def metadata_age_days
    SdwMemo.fetch(:metadata_age) do
      glob = case family
             when :apt then '/var/lib/apt/lists/*Release'
             when :dnf, :yum then '/var/cache/{dnf,yum}/*/repodata/repomd.xml'
             when :zypper then '/var/cache/zypp/raw/*/repodata/repomd.xml'
             end
      next nil unless glob

      out = cmd_ok("bash -c 'ls -1 #{glob} 2>/dev/null | xargs -r stat -c %Y 2>/dev/null | sort -n | tail -1'").to_s.strip
      if out.empty?
        nil
      else
        now = cmd_ok('date +%s').to_s.strip.to_i
        ((now - out.to_i) / 86_400.0).round(1)
      end
    end
  end

  def automatic_updates
    SdwAutoUpdates.new(self)
  end

  def runtime_kernel
    cmd_ok('uname -r').to_s.strip
  end

  # Newest installed kernel (what the next boot will run by default).
  def persistent_kernel
    SdwMemo.fetch(:newest_kernel) do
      if which('rpm')
        out = cmd_ok("rpm -q kernel kernel-core kernel-uek --qf '%{INSTALLTIME} %{VERSION}-%{RELEASE}.%{ARCH}\\n' 2>/dev/null | grep -v 'not installed'").to_s
        out.lines.map(&:split).max_by { |t, _| t.to_i }&.last
      else
        out = cmd_ok("ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's#/boot/vmlinuz-##' | sort -V | tail -1").to_s.strip
        out.empty? ? nil : out
      end
    end
  end

  def kernel_installed?
    !persistent_kernel.nil?
  end

  def reboot_required_flag
    inspec.file('/var/run/reboot-required').exist?
  end

  # Processes still mapping a shared library that was replaced on disk:
  # patched files, vulnerable memory.
  def processes_with_deleted_libs
    SdwMemo.fetch(:deleted_libs) do
      out = cmd_ok("grep -lsE '\\.so(\\.[0-9]+)*( \\(deleted\\)|;[0-9a-f]+ \\(deleted\\))' /proc/[0-9]*/maps 2>/dev/null").to_s
      pids = out.lines.map { |l| l[%r{/proc/(\d+)/maps}, 1] }.compact.uniq
      pids.first(200).filter_map do |pid|
        comm = read_file("/proc/#{pid}/comm").to_s.strip
        comm.empty? ? nil : "#{comm} (pid #{pid})"
      end.uniq { |s| s.split(' (').first }
    end
  end

  def to_s
    "updates (#{family || 'unknown package manager'})"
  end
end

class ::SdwAutoUpdates
  def initialize(upd)
    @upd = upd
  end

  # Configured to apply security updates unattended.
  def persistent
    case @upd.family
    when :apt
      cfg = @upd.cmd_ok('apt-config dump 2>/dev/null').to_s
      on = ->(k) { cfg =~ /^#{Regexp.escape(k)} "(1|true|always)";/ }
      on.call('APT::Periodic::Update-Package-Lists') && on.call('APT::Periodic::Unattended-Upgrade') &&
        !@upd.inspec.sdw_packages.installed('unattended-upgrades').empty?
    when :dnf, :yum
      %w[dnf-automatic-install.timer dnf-automatic.timer dnf5-automatic.timer yum-cron.service].any? do |u|
        next false unless @upd.inspec.sdw_unit(u).persistent_enabled
        next true if u.include?('install')

        conf = @upd.inspec.sdw_kv('/etc/dnf/automatic.conf', sep: '=', section: 'commands')
        conf.value('apply_updates').to_s =~ /yes|true|1/
      end
    else
      false
    end
  end

  def to_s
    'automatic security updates'
  end
  alias inspect to_s
end

# Operating system release and its support status.
class ::SdwOs < Inspec.resource(1)
  name 'sdw_os'
  desc 'os-release and end-of-support date.'
  example "describe sdw_os do\n  its('days_until_eol') { should be > 0 }\nend"

  include SdwHelpers

  def release
    SdwMemo.fetch(:os_release) do
      text = read_file('/etc/os-release') || read_file('/usr/lib/os-release') || ''
      text.lines.to_h do |l|
        k, v = l.strip.split('=', 2)
        [k, v.to_s.delete_prefix('"').delete_suffix('"')]
      end
    end
  end

  def id
    release['ID']
  end

  def version_id
    release['VERSION_ID'].to_s
  end

  def family
    ids = ([id] + release['ID_LIKE'].to_s.split).compact
    return 'debian' if ids.any? { |i| %w[debian ubuntu].include?(i) }
    return 'rhel' if ids.any? { |i| %w[rhel fedora centos rocky almalinux ol].include?(i) }
    return 'suse' if ids.any? { |i| i.include?('suse') }

    id
  end

  # Looks the release up in an {"id major" => "YYYY-MM-DD"} table.
  def eol_date(table)
    major = version_id.split('.').first
    key = [id, version_id].join(' ')
    key_major = [id, major].join(' ')
    d = table[key] || table[key_major]
    d ? Date.parse(d) : nil
  end

  def days_until_eol(table)
    d = eol_date(table)
    d ? (d - Date.today).to_i : nil
  end

  def to_s
    "#{release['PRETTY_NAME'] || 'operating system'}"
  end
end
