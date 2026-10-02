# frozen_string_literal: true

# Key/value configuration file resolved with its drop-in directory, the way the
# consuming program reads it (main file first, then drop-ins in lexical order,
# last assignment wins). Tracks where each effective value comes from.
class ::SdwKv < Inspec.resource(1)
  name 'sdw_kv'
  desc 'Effective key/value settings of a config file and its drop-ins.'
  example "describe sdw_kv('/etc/login.defs').setting('PASS_MAX_DAYS') do\n  its('value') { should cmp <= 365 }\nend"

  include SdwHelpers

  attr_reader :path

  # sep: :space ("KEY VALUE"), '=' ("key = value"), section: only read keys in [section].
  # InSpec passes resource options as a trailing positional hash.
  def initialize(path, opts = {})
    @path = path
    @sep = opts.fetch(:sep, :space)
    @dropins = opts[:dropins]
    @section = opts[:section]
    @casefold = opts.fetch(:casefold, false)
  end

  def exists?
    !files.empty?
  end

  def files
    SdwMemo.fetch([:kv_files, @path, @dropins]) do
      f = []
      f << @path if read_file(@path)
      f.concat(list_dir(@dropins, '*.conf')) if @dropins
      f
    end
  end

  def settings
    SdwMemo.fetch([:kv, @path, @dropins, @section, @sep]) do
      h = {}
      files.each do |f|
        cur = nil
        (read_file(f) || '').each_line.with_index(1) do |raw, n|
          line = raw.strip
          next if line.empty? || line.start_with?('#', ';')

          if (m = line.match(/\A\[(.+)\]\z/))
            cur = m[1]
            next
          end
          next if @section && cur != @section

          k, v = if @sep == :space
                   line.split(/\s+/, 2)
                 else
                   a, b = line.split(@sep, 2)
                   [a, b.nil? ? 'true' : b]
                 end
          next if k.nil? || k.empty?

          k = k.strip
          k = k.downcase if @casefold
          h[k] = { value: v.to_s.strip.delete_prefix('"').delete_suffix('"'), file: f, line: n }
        end
      end
      h
    end
  end

  def value(key)
    settings[@casefold ? key.downcase : key]&.dig(:value)
  end

  def setting(key)
    SdwKvSetting.new(self, key)
  end

  def source(key)
    e = settings[@casefold ? key.downcase : key]
    e ? "#{e[:file]}:#{e[:line]}" : nil
  end

  def to_s
    "config #{@path}"
  end
end

class ::SdwKvSetting
  def initialize(kv, key)
    @kv = kv
    @key = key
  end

  def value
    @kv.value(@key)
  end

  def to_s
    src = @kv.source(@key)
    "#{@key} (#{src ? "set in #{src}" : "not set in #{@kv.path}"})"
  end
  alias inspect to_s
end

# Password quality: pwquality.conf + drop-ins, overridden by pam_pwquality
# arguments in the effective PAM password stack (what passwd really enforces).
class ::SdwPwquality < Inspec.resource(1)
  name 'sdw_pwquality'
  desc 'Effective password quality policy (PAM arguments over pwquality.conf).'
  example "describe sdw_pwquality do\n  its('minlen') { should cmp >= 14 }\nend"

  include SdwHelpers

  def password_stack
    SdwMemo.fetch(:pw_stack) do
      svc = %w[common-password system-auth passwd].find { |s| inspec.file("/etc/pam.d/#{s}").exist? }
      svc ? inspec.sdw_pam(svc).stack('password') : nil
    end
  end

  def module_name
    return nil unless password_stack

    %w[pam_pwquality.so pam_cracklib.so pam_passwdqc.so].find { |m| password_stack.include?(m) }
  end

  def enabled
    !module_name.nil?
  end

  def conf
    @conf ||= inspec.sdw_kv('/etc/security/pwquality.conf', sep: '=', dropins: '/etc/security/pwquality.conf.d')
  end

  # libpwquality compiled-in defaults, used when neither PAM nor the config set a value.
  DEFAULTS = { 'minlen' => '8', 'minclass' => '0', 'dcredit' => '0', 'ucredit' => '0', 'lcredit' => '0', 'ocredit' => '0',
               'maxrepeat' => '0', 'maxsequence' => '0', 'dictcheck' => '1', 'difok' => '1' }.freeze

  # nil when no quality module is in the password stack: settings that PAM
  # never reads enforce nothing.
  def get(key)
    return nil unless module_name

    args = password_stack.args(module_name)
    return args[key] if args.key?(key)

    conf.value(key) || (module_name == 'pam_pwquality.so' ? DEFAULTS[key] : nil)
  end

  %w[minlen minclass dcredit ucredit lcredit ocredit maxrepeat maxsequence dictcheck difok].each do |k|
    define_method(k) { get(k)&.to_s }
  end

  def enforce_for_root
    return false unless module_name

    password_stack.args(module_name).key?('enforce_for_root') || !conf.value('enforce_for_root').nil?
  end

  # Character classes required, from minclass or negative credits.
  def classes_required
    by_credit = %w[dcredit ucredit lcredit ocredit].count { |k| get(k).to_i.negative? }
    [minclass.to_i, by_credit].max
  end

  def to_s
    "password quality (#{module_name || 'no pam_pwquality in password stack'})"
  end
end

# Kernel command line: runtime (/proc/cmdline) and what the boot loader will
# pass on next boot (grubby/BLS on RHEL-family, grub.cfg or /etc/default/grub).
class ::SdwCmdline < Inspec.resource(1)
  name 'sdw_cmdline'
  desc 'Kernel boot parameter: present on the running kernel, and in the boot loader config.'
  example "describe sdw_cmdline('audit') do\n  its('runtime') { should cmp '1' }\n  its('persistent') { should cmp '1' }\nend"

  include SdwHelpers

  def initialize(param)
    @param = param
  end

  def runtime
    self.class.lookup(read_file('/proc/cmdline').to_s, @param)
  end

  def persistent
    self.class.lookup(persistent_line, @param)
  end

  def persistent_origin
    persistent_sources.first&.first || 'none'
  end

  # Full kernel command line of the next boot (best source available).
  def boot_line
    persistent_line
  end

  def self.lookup(line, param)
    val = nil
    line.to_s.split(/\s+/).each do |tok|
      k, v = tok.split('=', 2)
      val = (v.nil? ? 'true' : v) if k == param
    end
    val
  end

  def to_s
    "kernel parameter #{@param} (boot config: #{persistent_origin})"
  end

  private

  def persistent_line
    persistent_sources.first&.last.to_s
  end

  def persistent_sources
    SdwMemo.fetch(:cmdline_persist) do
      src = []
      if which('grubby')
        out = cmd_ok('grubby --info=DEFAULT 2>/dev/null').to_s
        args = out[/^args="?([^"\n]*)"?/, 1]
        src << ['grubby DEFAULT entry', args] if args
      end
      kc = read_file('/etc/kernel/cmdline')
      src << ['/etc/kernel/cmdline', kc.strip] if kc
      %w[/boot/grub/grub.cfg /boot/grub2/grub.cfg].each do |cfg|
        text = read_file(cfg)
        next unless text

        line = text.lines.find { |l| l =~ /^\s*linux(efi)?\s+\S*vmlinuz/ }
        src << [cfg, line.to_s.strip] if line
      end
      dg = read_file('/etc/default/grub')
      if dg
        parts = dg.lines.grep(/^\s*GRUB_CMDLINE_LINUX(_DEFAULT)?=/).map { |l| l.split('=', 2).last.strip.delete_prefix('"').delete_suffix('"') }
        src << ['/etc/default/grub', parts.join(' ')] unless parts.empty?
      end
      src
    end
  end
end

# pam_limits configuration (limits.conf + limits.d, lexical order).
class ::SdwLimits < Inspec.resource(1)
  name 'sdw_limits'
  desc 'Resource limits applied by pam_limits.'
  example "describe sdw_limits do\n  its('hard_core_for_all') { should include '0' }\nend"

  include SdwHelpers

  def entries
    SdwMemo.fetch(:limits) do
      files = ['/etc/security/limits.conf'] + list_dir('/etc/security/limits.d', '*.conf')
      files.flat_map do |f|
        meaningful_lines(read_file(f)).filter_map do |l|
          t = l.split
          { domain: t[0], type: t[1], item: t[2], value: t[3], file: f } if t.size >= 4
        end
      end
    end
  end

  # Values of '* hard core' (or '* - core') lines, in file order.
  def hard_core_for_all
    entries.select { |e| e[:domain] == '*' && %w[hard -].include?(e[:type]) && e[:item] == 'core' }.map { |e| e[:value] }
  end

  # pam_limits keeps the last matching entry.
  def effective_hard_core
    hard_core_for_all.last
  end

  def to_s
    'pam_limits (limits.conf, limits.d)'
  end
end
