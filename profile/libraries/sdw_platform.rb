# frozen_string_literal: true

# Mandatory access control (SELinux or AppArmor): enforcing now, and still
# enforcing after the next boot.
class ::SdwMac < Inspec.resource(1)
  name 'sdw_mac'
  desc 'SELinux/AppArmor state: runtime mode and boot configuration.'
  example "describe sdw_mac do\n  its('runtime_enforcing') { should cmp true }\n  its('persistent_enforcing') { should cmp true }\nend"

  include SdwHelpers

  def framework
    SdwMemo.fetch(:mac_framework) do
      if inspec.file('/sys/fs/selinux/enforce').exist? || inspec.file('/etc/selinux/config').exist? && which('getenforce')
        'selinux'
      elsif inspec.file('/sys/module/apparmor/parameters/enabled').exist? || which('apparmor_parser')
        'apparmor'
      end
    end
  end

  def runtime_enforcing
    case framework
    when 'selinux'
      read_file('/sys/fs/selinux/enforce').to_s.strip == '1'
    when 'apparmor'
      read_file('/sys/module/apparmor/parameters/enabled').to_s.strip == 'Y' && apparmor_profiles.any? { |p| p.end_with?('(enforce)') }
    else
      false
    end
  end

  def persistent_enforcing
    cmd = inspec.sdw_cmdline('selinux')
    boot = cmd.boot_line.to_s
    case framework
    when 'selinux'
      conf = inspec.sdw_kv('/etc/selinux/config', sep: '=')
      conf.value('SELINUX').to_s == 'enforcing' && boot !~ /(^|\s)(selinux=0|enforcing=0)(\s|$)/
    when 'apparmor'
      unit = inspec.sdw_unit('apparmor.service')
      (unit.persistent_enabled || unit.unit_file_state.to_s == 'static' || !unit.exists?) &&
        boot !~ /(^|\s)apparmor=0(\s|$)/ && boot !~ /(^|\s)security=(?!apparmor)\S+/
    else
      false
    end
  end

  def apparmor_profiles
    SdwMemo.fetch(:aa_profiles) do
      (read_file('/sys/kernel/security/apparmor/profiles') || '').lines.map(&:strip).reject(&:empty?)
    end
  end

  def to_s
    case framework
    when 'selinux' then 'SELinux'
    when 'apparmor' then "AppArmor (#{apparmor_profiles.size} profiles loaded)"
    else 'mandatory access control (none found)'
    end
  end
end

# Firmware / boot chain facts.
class ::SdwBoot < Inspec.resource(1)
  name 'sdw_boot'
  desc 'UEFI Secure Boot, kernel lockdown, NX support, boot loader password.'
  example "describe sdw_boot do\n  its('secure_boot') { should cmp true }\nend"

  include SdwHelpers

  def efi?
    inspec.directory('/sys/firmware/efi').exist?
  end

  def secure_boot
    SdwMemo.fetch(:secure_boot) do
      if which('mokutil')
        cmd_ok('mokutil --sb-state 2>/dev/null').to_s =~ /SecureBoot enabled/ ? true : false
      else
        out = cmd_ok("od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null").to_s.split
        out.last == '1'
      end
    end
  end

  def lockdown
    read_file('/sys/kernel/security/lockdown').to_s[/\[(\w+)\]/, 1] || 'none'
  end

  def cpu_nx
    (read_file('/proc/cpuinfo') || '').lines.grep(/^flags/).first.to_s.split.include?('nx')
  end

  def grub_configs
    %w[/boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg].flat_map do |g|
      g.include?('*') ? list_dir(File.dirname(g).sub('/*', ''), '*/grub.cfg') : [g]
    end.select { |f| inspec.file(f).exist? }
  end

  def grub_password
    texts = grub_configs.map { |f| read_file(f).to_s }
    texts += %w[/boot/grub2/user.cfg /boot/grub/user.cfg].map { |f| read_file(f).to_s }
    all = texts.join("\n")
    (all =~ /^\s*set\s+superusers\s*=/ && all =~ /^\s*password_pbkdf2\s+\S+\s+grub\.pbkdf2/) || all =~ /^GRUB2_PASSWORD=grub\.pbkdf2/ ? true : false
  end

  def to_s
    'boot chain'
  end
end

# File integrity monitoring (AIDE).
class ::SdwFim < Inspec.resource(1)
  name 'sdw_fim'
  desc 'AIDE installation, database and schedule.'
  example "describe sdw_fim do\n  its('database') { should_not be_nil }\nend"

  include SdwHelpers

  DBS = %w[/var/lib/aide/aide.db /var/lib/aide/aide.db.gz /var/lib/aide/aide.db.new /var/lib/aide/aide.db.new.gz].freeze

  def installed
    !which('aide').nil?
  end

  def database
    DBS.find { |d| inspec.file(d).exist? }
  end

  # The unit or cron file that runs the periodic check.
  def schedule
    SdwMemo.fetch(:fim_schedule) do
      found = %w[sdw-aidecheck.timer dailyaidecheck.timer aidecheck.timer aide-check.timer].find { |u| inspec.sdw_unit(u).persistent_enabled }
      unless found
        out = cmd_ok("grep -lsE '(^|[^#]*)(aide|aide\\.wrapper|aideinit)' /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.weekly/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null").to_s.lines.first
        found = out.to_s.strip unless out.to_s.strip.empty?
      end
      found
    end
  end

  def scheduled
    !schedule.nil?
  end

  def to_s
    "file integrity monitoring (#{installed ? 'AIDE' : 'AIDE not installed'})"
  end
end

# Services by role: which of several alternatives (chrony vs timesyncd...) is
# running now and enabled at boot.
class ::SdwServiceSet < Inspec.resource(1)
  name 'sdw_service_set'
  desc 'Alternative units for one role: which are active now, which start at boot.'
  example "describe sdw_service_set('time sync', %w[chrony.service systemd-timesyncd.service]) do\n  its('runtime_any_active') { should cmp true }\nend"

  include SdwHelpers

  def initialize(role, units)
    @role = role
    @units = units
  end

  # Units active now / enabled at boot (lists, for "must not run" checks).
  def runtime_active
    @units.select { |u| inspec.sdw_unit(u).runtime_active }
  end

  def persistent_enabled
    @units.select { |u| inspec.sdw_unit(u).persistent_enabled }
  end

  # Booleans, for "one of them must run" checks.
  def runtime_any_active
    !runtime_active.empty?
  end

  def persistent_any_enabled
    !persistent_enabled.empty?
  end

  def to_s
    installed = @units.select { |u| inspec.sdw_unit(u).exists? }
    "#{@role} [#{installed.empty? ? 'none installed' : installed.join(', ')}]"
  end
end

# Evidence helper: a named list that should be empty (or not). Makes
# failures print the offending items instead of "expected [] to be empty".
class ::SdwFindings
  attr_reader :items

  def initialize(label, items)
    @label = label
    @items = Array(items)
  end

  def to_s
    @label
  end
  alias inspect to_s
end

# Evidence helper for a single computed value.
class ::SdwValue
  attr_reader :value

  def initialize(label, value)
    @label = label
    @value = value
  end

  def to_s
    @label
  end
  alias inspect to_s
end

# Evidence helper for a state proven twice: now, and after reboot.
class ::SdwState
  attr_reader :runtime, :persistent

  def initialize(label, runtime:, persistent:)
    @label = label
    @runtime = runtime
    @persistent = persistent
  end

  def to_s
    @label
  end
  alias inspect to_s
end
