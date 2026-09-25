# frozen_string_literal: true

# systemd units, audited on two axes:
#   runtime_active      -> is it running right now (ActiveState)
#   persistent_enabled  -> will it come back after a reboot (UnitFileState)
# A service that was stopped but is still enabled passes "runtime" only.
class ::SdwSystemd < Inspec.resource(1)
  name 'sdw_systemd'
  desc 'Is systemd the running init, and effective drop-in resolution of its config files.'
  example "sdw_systemd.running?\nsdw_systemd.cat_config('systemd/journald.conf')"

  include SdwHelpers

  def available?
    !which('systemctl').nil?
  end

  # True when systemd is PID 1 (not the case in most containers).
  def running?
    SdwMemo.fetch(:systemd_running) do
      d = inspec.directory('/run/systemd/system')
      d.exist? && d.directory?
    end
  end

  # Effective key/value settings of a systemd config file and all its drop-ins,
  # resolved by `systemd-analyze cat-config` (same precedence as the daemons).
  # Returns {"Section" => {"Key" => "value"}}; later assignments win.
  def cat_config(name)
    SdwMemo.fetch([:cat_config, name]) do
      text = nil
      text = cmd_ok("systemd-analyze cat-config #{Shellwords.escape(name)} 2>/dev/null") if which('systemd-analyze')
      text ||= fallback_cat(name)
      parse_ini(text)
    end
  end

  def to_s
    'systemd'
  end

  private

  def fallback_cat(name)
    parts = []
    main = ["/etc/#{name}", "/usr/lib/#{name}", "/lib/#{name}"].map { |p| read_file(p) }.compact.first
    parts << main if main
    dropins = {}
    %W[/usr/lib/#{name}.d /lib/#{name}.d /run/#{name}.d /etc/#{name}.d].each do |d|
      list_dir(d, '*.conf').each { |f| dropins[File.basename(f)] = f }
    end
    dropins.keys.sort.each { |b| parts << read_file(dropins[b]).to_s }
    parts.join("\n")
  end

  def parse_ini(text)
    res = Hash.new { |h, k| h[k] = {} }
    section = nil
    text.to_s.each_line do |raw|
      line = raw.strip
      next if line.empty? || line.start_with?('#', ';')

      if (m = line.match(/\A\[(.+)\]\z/))
        section = m[1]
        next
      end
      k, v = line.split('=', 2)
      next unless v && section

      res[section][k.strip] = v.strip
    end
    res.default_proc = nil
    res
  end
end

class ::SdwUnit < Inspec.resource(1)
  name 'sdw_unit'
  desc 'A systemd unit: live state (runtime_active) and boot state (persistent_enabled).'
  example "describe sdw_unit('avahi-daemon.service') do\n  its('runtime_active') { should cmp false }\n  its('persistent_enabled') { should cmp false }\nend"

  include SdwHelpers

  def initialize(unit)
    @unit = unit.include?('.') ? unit : "#{unit}.service"
  end

  def exists?
    props['LoadState'] && !%w[not-found].include?(props['LoadState']) && !props['LoadState'].empty?
  end

  def masked?
    props['LoadState'] == 'masked' || props['UnitFileState'].to_s.start_with?('masked')
  end

  def runtime_active
    return false unless exists?

    %w[active activating reloading refreshing].include?(props['ActiveState'])
  end

  def persistent_enabled
    return false unless exists?

    %w[enabled enabled-runtime alias linked linked-runtime].include?(props['UnitFileState'].to_s) ||
      (props['UnitFileState'].to_s == 'static' && wanted?)
  end

  def unit_file_state
    props['UnitFileState']
  end

  def active_state
    props['ActiveState']
  end

  def to_s
    "systemd unit #{@unit}"
  end

  private

  # A static unit counts as enabled when something wants it (e.g. a socket).
  def wanted?
    out = cmd_ok("systemctl list-dependencies --reverse --plain --no-legend #{Shellwords.escape(@unit)} 2>/dev/null")
    out.to_s.lines.map(&:strip).reject { |l| l.empty? || l == @unit }.any?
  end

  def props
    SdwMemo.fetch([:unit, @unit]) do
      h = {}
      out = cmd_ok("systemctl show --no-pager -p LoadState,ActiveState,SubState,UnitFileState,FragmentPath #{Shellwords.escape(@unit)} 2>/dev/null")
      out.to_s.each_line do |l|
        k, v = l.strip.split('=', 2)
        h[k] = v.to_s if k
      end
      # Without a running systemd (containers), fall back to the unit files.
      if h.empty? || h['LoadState'].to_s.empty?
        st = cmd_ok("systemctl is-enabled #{Shellwords.escape(@unit)} 2>/dev/null").to_s.strip
        st = sh("systemctl is-enabled #{Shellwords.escape(@unit)} 2>&1").stdout.to_s.strip if st.empty?
        if st.empty? || st =~ /No such file|not found|Failed to get/i
          h = { 'LoadState' => 'not-found', 'ActiveState' => 'inactive', 'UnitFileState' => '' }
        else
          h = { 'LoadState' => st == 'masked' ? 'masked' : 'loaded', 'ActiveState' => 'unknown', 'UnitFileState' => st }
        end
      end
      h
    end
  end
end
