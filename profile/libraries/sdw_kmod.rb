# frozen_string_literal: true

# Kernel module that should not be available:
#   runtime_loaded       -> present in /proc/modules right now
#   persistent_disabled  -> the effective modprobe configuration (`modprobe
#                           --showconfig`, i.e. every modprobe.d merged) makes
#                           loading it a no-op, or the module does not exist.
class ::SdwKmod < Inspec.resource(1)
  name 'sdw_kmod'
  desc 'Kernel module availability: loaded now, and loadable after reboot.'
  example "describe sdw_kmod('cramfs') do\n  its('runtime_loaded') { should cmp false }\n  its('persistent_disabled') { should cmp true }\nend"

  include SdwHelpers

  FALSE_CMDS = %r{\A(/usr)?/bin/(false|true)\z}

  def initialize(name)
    @name = name
    @key = name.tr('-', '_')
  end

  def runtime_loaded
    loaded = SdwMemo.fetch(:proc_modules) do
      (read_file('/proc/modules') || '').lines.map { |l| l.split.first }.compact
    end
    loaded.include?(@key)
  end

  def persistent_disabled
    return false if builtin?

    cfg = showconfig
    install = cfg[:install][@key]
    return true if install && install.split.first.to_s =~ FALSE_CMDS
    return true unless exists?

    false
  end

  def blacklisted
    showconfig[:blacklist].include?(@key)
  end

  def builtin?
    list = SdwMemo.fetch(:modules_builtin) do
      rel = cmd_ok('uname -r').to_s.strip
      (read_file("/lib/modules/#{rel}/modules.builtin") || '').lines.map { |l| File.basename(l.strip, '.ko').tr('-', '_') }
    end
    list.include?(@key)
  end

  def exists?
    return true if builtin?

    SdwMemo.fetch([:modinfo, @key]) { sh("modinfo -n #{Shellwords.escape(@name)} >/dev/null 2>&1").exit_status.zero? }
  end

  def to_s
    "kernel module #{@name}"
  end

  private

  def showconfig
    SdwMemo.fetch(:modprobe_showconfig) do
      res = { install: {}, blacklist: [] }
      out = which('modprobe') ? cmd_ok('modprobe --showconfig 2>/dev/null') : nil
      out.to_s.each_line do |l|
        parts = l.strip.split(/\s+/, 3)
        case parts[0]
        when 'install' then res[:install][parts[1].to_s.tr('-', '_')] = parts[2].to_s.strip
        when 'blacklist' then res[:blacklist] << parts[1].to_s.tr('-', '_')
        end
      end
      res
    end
  end
end
