# frozen_string_literal: true

# Kernel parameter, audited twice:
#   runtime    -> the live value (/proc/sys via `sysctl -n`)
#   persistent -> the value the boot-time loader will apply, resolved exactly
#                 like systemd-sysctl: every *.conf of the sysctl.d directories,
#                 same-name files shadowed by precedence (/etc > /run > /usr/local/lib > /usr/lib > /lib),
#                 applied in lexical order, last assignment wins, explicit keys win
#                 over globs. /etc/sysctl.conf is applied last (procps behaviour).
class ::SdwSysctl < Inspec.resource(1)
  name 'sdw_sysctl'
  desc 'Kernel parameter: live value and boot-persisted value (with the file that sets it).'
  example "describe sdw_sysctl('kernel.randomize_va_space') do\n  its('runtime') { should cmp 2 }\n  its('persistent') { should cmp 2 }\nend"

  include SdwHelpers

  DIRS = %w[/etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d].freeze

  attr_reader :key

  # absent_ok: a key missing from the running kernel means the feature does
  # not exist (e.g. IPv6 disabled), which is compliant: the check is skipped.
  # InSpec passes resource options as a trailing positional hash.
  def initialize(key, opts = {})
    @key = key.tr('/', '.')
    @absent_ok = opts[:absent_ok] || opts['absent_ok'] || false
    # Skipping must happen here: InSpec only honours ResourceSkipped raised
    # while the resource is being built, not from a property.
    raise ::Inspec::Exceptions::ResourceSkipped, "#{@key} does not exist on this kernel (feature absent)" if @absent_ok && live.nil?
  end

  def exists?
    !live.nil?
  end

  def runtime
    live
  end

  def persistent
    entry = self.class.persisted(inspec, self)[:explicit][@key] || glob_match
    entry && entry[:value]
  end

  # File (and line) that defines the persisted value, for evidence.
  def persistent_source
    entry = self.class.persisted(inspec, self)[:explicit][@key] || glob_match
    entry ? "#{entry[:file]}:#{entry[:line]}" : 'not persisted'
  end

  def to_s
    src = begin
      persistent_source
    rescue StandardError
      'unknown'
    end
    "sysctl #{@key} [boot value: #{src}]"
  end

  def self.persisted(inspec, res)
    SdwMemo.fetch(:sysctl_persisted) do
      files = {}
      DIRS.reverse_each do |d|
        res.list_dir(d, '*.conf').each { |f| files[File.basename(f)] = f }
      end
      ordered = files.keys.sort.map { |b| files[b] }
      # /etc/sysctl.conf is read last by `sysctl --system`; when it is already
      # linked as /etc/sysctl.d/99-sysctl.conf its content is simply applied twice.
      ordered << '/etc/sysctl.conf'
      explicit = {}
      globs = []
      ordered.each do |f|
        content = res.read_file(f)
        next unless content

        content.each_line.with_index(1) do |raw, n|
          line = raw.strip
          next if line.empty? || line.start_with?('#', ';')

          k, v = line.split('=', 2)
          next unless v

          k = k.strip.sub(/\A-/, '').tr('/', '.')
          entry = { value: normalize_value(v), file: f, line: n }
          if k.include?('*') || k.include?('?')
            globs << [k, entry]
          else
            explicit[k] = entry
          end
        end
      end
      { explicit: explicit, globs: globs }
    end
  end

  def self.normalize_value(v)
    v.to_s.strip.split(/\s+/).join(' ')
  end

  private

  def live
    SdwMemo.fetch([:sysctl_rt, @key]) do
      path = "/proc/sys/#{@key.tr('.', '/')}"
      r = sh("cat #{path} 2>/dev/null")
      r.exit_status.zero? ? normalize(r.stdout) : nil
    end
  end

  def normalize(v)
    self.class.normalize_value(v)
  end

  def glob_match
    self.class.persisted(inspec, self)[:globs].reverse.find { |k, _| File.fnmatch(k, @key) }&.last
  end
end
