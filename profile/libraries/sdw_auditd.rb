# frozen_string_literal: true

# Linux audit subsystem, audited twice:
#   runtime_*    -> the rules the kernel enforces now (`auditctl -l`, `auditctl -s`)
#   persistent_* -> the rules loaded at boot (rules.d merged the way augenrules
#                   does, or audit.rules when rules.d is empty)
class ::SdwAuditd < Inspec.resource(1)
  name 'sdw_auditd'
  desc 'Kernel audit rules: loaded now (auditctl) and loaded at boot (rules.d).'
  example "describe sdw_auditd.watch('/etc/shadow', 'wa') do\n  its('runtime') { should cmp true }\n  its('persistent') { should cmp true }\nend"

  include SdwHelpers

  def installed?
    !which('auditctl').nil?
  end

  # Raw loaded rules, or nil when the kernel audit subsystem is not readable.
  def runtime_rules
    SdwMemo.fetch(:auditctl_l) do
      next nil unless installed?

      r = sh('auditctl -l 2>&1')
      out = r.stdout.to_s
      if r.exit_status.zero? && out !~ /Operation not permitted|Error sending/i
        out.lines.map(&:strip).reject { |l| l.empty? || l =~ /\ANo rules\z/ }
      elsif cmd_ok('id -u').to_s.strip == '0'
        # root, yet the kernel refuses: no audit support here, so no rule is loaded.
        []
      end
    end
  end

  def runtime_status
    SdwMemo.fetch(:auditctl_s) do
      next {} unless installed?

      out = cmd_ok('auditctl -s 2>/dev/null')
      out.to_s.lines.to_h { |l| k, v = l.strip.split(/\s+/, 2); [k, v.to_s] }
    end
  end

  def persistent_rules
    SdwMemo.fetch(:audit_persisted) do
      # augenrules reads rules.d in natural order (ls -v).
      files = list_dir('/etc/audit/rules.d', '*.rules').sort_by { |f| File.basename(f).split(/(\d+)/).map { |x| x =~ /\A\d+\z/ ? x.to_i : x } }
      files = ['/etc/audit/audit.rules'] if files.empty?
      files.flat_map { |f| meaningful_lines(read_file(f)) }
    end
  end

  def watch(path, perms)
    SdwAuditCheck.new(self, "watch #{path} (-p #{perms})") { |rules| rules.any? { |r| watch_rule?(r, path, perms) } }
  end

  def syscalls(names, arch: 'b64', extra: nil)
    label = "syscalls #{Array(names).join(',')} (#{arch}#{extra ? ", #{extra.source}" : ''})"
    SdwAuditCheck.new(self, label) do |rules|
      Array(names).all? { |n| rules.any? { |r| syscall_rule?(r, n, arch, extra) } }
    end
  end

  # augenrules emits the last -e directive it read as the final rule.
  def immutable
    SdwAuditCheck.new(self, 'configuration locked (-e 2)',
                      runtime_proc: -> { runtime_status['enabled'].to_s.strip == '2' }) do |rules|
      rules.grep(/\A-e\s+\d/).last.to_s =~ /\A-e\s+2\b/ ? true : false
    end
  end

  def to_s
    'audit rules'
  end

  def watch_rule?(rule, path, perms)
    toks = rule.split
    target = nil
    if (i = toks.index('-w'))
      target = toks[i + 1]
    elsif (m = rule.match(/-F\s+(?:path|dir)=(\S+)/))
      target = m[1]
    end
    return false unless target

    target = target.chomp('/')
    p = path.chomp('/')
    return false unless target == p || (p.start_with?("#{target}/") && rule.include?('dir='))

    got = rule[/-p\s+([rwxa]+)/, 1] || rule[/-F\s+perm=([rwxa]+)/, 1] || 'rwxa'
    perms.chars.all? { |c| got.include?(c) }
  end

  def syscall_rule?(rule, name, arch, extra)
    return false unless rule =~ /-a\s+(always,exit|exit,always)/
    return false if arch && rule =~ /arch=b(32|64)/ && rule !~ /arch=#{arch}\b/
    return false if extra && rule !~ extra

    rule.scan(/-S\s+(\S+)/).flatten.flat_map { |s| s.split(',') }.include?(name) ||
      rule =~ /-S\s+all\b/
  end
end

class ::SdwAuditCheck
  def initialize(auditd, label, runtime_proc: nil, &matcher)
    @auditd = auditd
    @label = label
    @runtime_proc = runtime_proc
    @matcher = matcher
  end

  def runtime
    return @runtime_proc.call if @runtime_proc

    rules = @auditd.runtime_rules
    raise ::Inspec::Exceptions::ResourceFailed, 'cannot read loaded audit rules (auditctl -l): auditd missing, not root, or no kernel audit support' if rules.nil?

    @matcher.call(rules)
  end

  def persistent
    @matcher.call(@auditd.persistent_rules)
  end

  def to_s
    "audit rule: #{@label}"
  end
  alias inspect to_s
end
