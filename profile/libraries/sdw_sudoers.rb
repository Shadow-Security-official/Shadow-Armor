# frozen_string_literal: true

# Effective sudo policy: /etc/sudoers plus every @include/@includedir
# (#include/#includedir) file, in the order sudo parses them. Global Defaults
# are resolved last-one-wins, as sudo does.
class ::SdwSudoers < Inspec.resource(1)
  name 'sdw_sudoers'
  desc 'Effective sudoers policy across all included files.'
  example "describe sdw_sudoers do\n  its('nopasswd_rules') { should be_empty }\nend"

  include SdwHelpers

  MAIN = '/etc/sudoers'

  def installed?
    !which('sudo').nil? || inspec.file(MAIN).exist?
  end

  def files
    parsed[:files]
  end

  # Effective global Defaults: {"use_pty" => true, "logfile" => "/var/log/sudo.log", "requiretty" => false}
  def defaults
    parsed[:defaults]
  end

  def default(name)
    defaults[name]
  end

  # User specification lines ("who host=(runas) [TAGS:] cmnds").
  def rules
    parsed[:rules]
  end

  def nopasswd_rules
    rules.select { |r| r[:text] =~ /NOPASSWD\s*:/ }.map { |r| "#{r[:file]}:#{r[:line]}: #{r[:text]}" } +
      defaults_with('!authenticate')
  end

  def negated_command_rules
    rules.select { |r| r[:text].split('=', 2).last.to_s =~ /(^|[,:\s])!\s*\//  }.map { |r| "#{r[:file]}:#{r[:line]}: #{r[:text]}" }
  end

  def to_s
    'sudoers policy'
  end

  private

  def defaults_with(flag)
    parsed[:raw_defaults].select { |d| d[:text].split(/[\s,]+/).include?(flag) }.map { |d| "#{d[:file]}:#{d[:line]}: #{d[:text]}" }
  end

  def parsed
    SdwMemo.fetch(:sudoers) do
      acc = { files: [], defaults: {}, raw_defaults: [], rules: [] }
      walk(MAIN, acc, 0)
      acc
    end
  end

  def walk(path, acc, depth)
    return if depth > 8

    content = read_file(path)
    return unless content

    acc[:files] << path
    logical_lines(content).each do |n, line|
      if (m = line.match(/\A[@#]includedir\s+(\S+)/))
        dir = m[1]
        # sudo skips files containing a '.' or ending in '~'.
        list_dir(dir).reject { |f| File.basename(f) =~ /[.~]/ }.each { |f| walk(f, acc, depth + 1) }
        next
      end
      if (m = line.match(/\A[@#]include\s+(\S+)/))
        inc = m[1]
        inc = File.join(File.dirname(path), inc) unless inc.start_with?('/')
        walk(inc, acc, depth + 1)
        next
      end
      next if line.start_with?('#')

      if line =~ /\ADefaults(\s|$)/
        acc[:raw_defaults] << { file: path, line: n, text: line }
        parse_defaults(line.sub(/\ADefaults\s*/, ''), acc[:defaults])
      elsif line =~ /\ADefaults[:@!>]/
        acc[:raw_defaults] << { file: path, line: n, text: line }
      elsif line !~ /\A(User|Runas|Host|Cmnd|Cmd)_Alias\b/
        acc[:rules] << { file: path, line: n, text: line }
      end
    end
  end

  # Joins backslash continuations, drops comments (but keeps #include lines).
  def logical_lines(content)
    out = []
    buf = +''
    start = nil
    content.each_line.with_index(1) do |raw, n|
      l = raw.rstrip
      start ||= n
      if l.end_with?('\\')
        buf << l.chomp('\\') << ' '
        next
      end
      buf << l
      text = buf.strip
      text = text.sub(/\s+#(?!include).*$/, '') unless text.start_with?('#include', '#includedir')
      out << [start, text] unless text.empty? || (text.start_with?('#') && text !~ /\A#include/)
      buf = +''
      start = nil
    end
    out
  end

  def parse_defaults(spec, into)
    split_top(spec).each do |item|
      item = item.strip
      next if item.empty?

      if (m = item.match(/\A(\w+)\s*([+\-]?=)\s*(.*)\z/))
        into[m[1]] = m[3].strip.delete_prefix('"').delete_suffix('"')
      elsif item.start_with?('!')
        into[item.delete_prefix('!').strip] = false
      else
        into[item] = true
      end
    end
  end

  # Split on commas that are not inside double quotes.
  def split_top(s)
    parts = []
    cur = +''
    q = false
    s.each_char do |ch|
      if ch == '"'
        q = !q
      elsif ch == ',' && !q
        parts << cur
        cur = +''
        next
      end
      cur << ch
    end
    parts << cur
  end
end
