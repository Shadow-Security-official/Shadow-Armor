# frozen_string_literal: true

# OpenSSH server, audited through `sshd -T`: the configuration sshd itself
# resolves (Include files, drop-ins, defaults, first-value-wins), not the text
# of /etc/ssh/sshd_config. The config files are still parsed, but only to say
# *which file* set the effective value, and to find Match blocks that relax it.
class ::SdwSshdConfig < Inspec.resource(1)
  name 'sdw_sshd'
  desc 'Effective OpenSSH server configuration (sshd -T) with the origin of each keyword.'
  example "describe sdw_sshd.option('PermitRootLogin') do\n  its('value') { should cmp 'no' }\nend"

  include SdwHelpers

  MAIN = '/etc/ssh/sshd_config'

  def installed?
    !binary.nil?
  end

  def binary
    which('sshd')
  end

  # Effective keyword => [values] (sshd -T prints multi-valued keywords once per value).
  def effective(spec = nil)
    SdwMemo.fetch([:sshd_t, spec]) do
      # Controls guard on installed? with only_if; an empty answer keeps
      # load-time evaluation of their bodies harmless.
      installed? ? run_t(spec) : {}
    end
  end

  def option(keyword)
    SdwSshdOption.new(self, keyword)
  end

  def value(keyword)
    v = effective[keyword.downcase]
    v&.first
  end

  def values(keyword)
    effective[keyword.downcase] || []
  end

  # "file:line" of the first global occurrence of keyword (sshd keeps the first
  # value it reads), or nil when sshd uses its compiled-in default.
  def source(keyword)
    k = keyword.downcase
    parsed[:global].find { |e| e[:key] == k }&.then { |e| "#{e[:file]}:#{e[:line]}" }
  end

  # [{condition:, file:, line:, settings: {key => value}}]
  def match_blocks
    parsed[:matches]
  end

  def config_files
    parsed[:files]
  end

  def to_s
    'sshd -T'
  end

  private

  def run_t(spec)
    arg = spec ? " -C #{Shellwords.escape(spec)}" : ''
    r = sh("#{binary} -T#{arg} 2>&1")
    out = r.stdout.to_s
    if r.exit_status != 0 || out !~ /^port /
      if (m = out.match(/Missing privilege separation directory: (\S+)/))
        # Socket-activated sshd (Ubuntu 24.04+) creates its privsep directory on
        # first connection. Resolve the config in a private mount namespace with
        # a throwaway tmpfs so nothing is written on the host.
        dir = m[1]
        parent = File.dirname(dir)
        wrapped = "unshare -m sh -c #{Shellwords.escape("mount -t tmpfs -o size=1m,mode=0755 sdw-armor #{parent} && mkdir -p #{dir} && exec #{binary} -T#{arg}")} 2>&1"
        r = sh(wrapped)
        out = r.stdout.to_s
      end
    end
    if r.exit_status != 0 || out !~ /^port /
      hint = out =~ /hostkeys|Permission denied|not permitted/i ? ' (sshd -T needs root: run as root or with --sudo)' : ''
      raise ::Inspec::Exceptions::ResourceFailed, "sshd -T failed#{hint}: #{out.strip.lines.first(3).join(' ').strip}"
    end
    h = Hash.new { |hash, key| hash[key] = [] }
    out.each_line do |line|
      k, v = line.strip.split(/\s+/, 2)
      next if k.nil? || k.empty?

      h[k.downcase] << normalize(k.downcase, v.to_s)
    end
    h.default_proc = nil
    h
  end

  # sshd -T prints the historical alias of PermitRootLogin prohibit-password.
  def normalize(key, value)
    key == 'permitrootlogin' && value.casecmp?('without-password') ? 'prohibit-password' : value
  end

  def parsed
    SdwMemo.fetch(:sshd_parsed) do
      acc = { global: [], matches: [], files: [] }
      walk(MAIN, acc, nil, 0)
      acc
    end
  end

  # Walks the configuration in the order sshd reads it.
  def walk(path, acc, match, depth)
    return match if depth > 16

    content = read_file(path)
    return match unless content

    acc[:files] << path unless acc[:files].include?(path)
    content.each_line.with_index(1) do |raw, n|
      line = raw.strip
      next if line.empty? || line.start_with?('#')

      key, rest = line.split(/[\s=]+/, 2)
      key = key.downcase
      rest = rest.to_s.strip
      case key
      when 'include'
        rest.split(/\s+/).each do |pat|
          pat = File.join('/etc/ssh', pat) unless pat.start_with?('/')
          expand(pat).each { |f| match = walk(f, acc, match, depth + 1) }
        end
      when 'match'
        match = { condition: rest, file: path, line: n, settings: {} }
        acc[:matches] << match unless rest.casecmp('all').zero?
        match = nil if rest.casecmp('all').zero?
      else
        rest = normalize(key, rest)
        if match
          match[:settings][key] ||= rest
        else
          acc[:global] << { key: key, value: rest, file: path, line: n }
        end
      end
    end
    match
  end

  def expand(pattern)
    return [pattern] unless pattern =~ /[*?\[]/

    dir = File.dirname(pattern)
    list_dir(dir, File.basename(pattern))
  end
end

# One sshd keyword, with its origin in the evidence string.
class ::SdwSshdOption
  def initialize(sshd, keyword)
    @sshd = sshd
    @keyword = keyword
  end

  def value
    @sshd.value(@keyword)
  end

  def values
    @sshd.values(@keyword)
  end

  def to_s
    src = begin
      @sshd.source(@keyword)
    rescue StandardError
      nil
    end
    "sshd -T #{@keyword} (#{src ? "set in #{src}" : 'sshd default'})"
  end
  alias inspect to_s
end
