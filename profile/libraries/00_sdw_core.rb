# frozen_string_literal: true

# Shadow-Armor core helpers.
#
# Every effective-state resource in this profile follows the same contract:
#   * properties named `runtime*`    describe what the running system does now;
#   * properties named `persistent*` describe what the host will do after a reboot
#     (or a service reload) according to its persisted configuration;
#   * any other property is "effective": the resolved configuration as the
#     service itself computes it (e.g. `sshd -T`), which is durable by nature.
# The Shadow-Armor CLI turns that naming into a qualified verdict
# (durable pass, runtime-only pass, pending fix, fail).

require 'json'
require 'shellwords'

# Process-wide memo. cinc-auditor audits exactly one target per process, so a
# plain module-level cache is safe and avoids re-running the same probe (which
# is one SSH round trip per command in remote mode).
module ::SdwMemo
  @store = {}
  class << self
    def fetch(key)
      return @store[key] if @store.key?(key)

      @store[key] = yield
    end

    def reset!
      @store = {}
    end
  end
end

# A control skipped by a first only_if keeps that reason: InSpec would let a
# later only_if overwrite the message (and run its probe for nothing), so a
# host-scoped control inside a container would report the wrong cause.
module ::SdwFirstSkipReason
  def only_if(*args, **opts, &block)
    return if block && @__skip_rule.is_a?(Hash) && @__skip_rule[:result]

    super
  end
end
::Inspec::Rule.prepend(::SdwFirstSkipReason)

class ::SdwCatalog < Inspec.resource(1)
  name 'sdw_catalog'
  desc 'The Shadow-Armor catalog: control metadata, standard mappings and input defaults.'
  example "sdw_catalog.apply(self, 'SA-06.01')"

  def data
    SdwMemo.fetch(:catalog) { JSON.parse(inspec.profile.file('catalog.json')) }
  end

  def control(id)
    SdwMemo.fetch([:catalog_index]) { data.fetch('controls').to_h { |c| [c['id'], c] } }[id] or
      raise ::Inspec::Exceptions::ResourceFailed, "control #{id} is missing from files/catalog.json"
  end

  # Default value of a Shadow-Armor input, so the profile also works standalone.
  def default(name)
    entry = data.fetch('inputs').find { |i| i['name'] == name }
    raise ::Inspec::Exceptions::ResourceFailed, "input #{name} is not declared in files/catalog.json" unless entry

    entry['value']
  end

  IMPACT = { 'critical' => 1.0, 'high' => 0.7, 'medium' => 0.5, 'low' => 0.3, 'info' => 0.0 }.freeze

  # Applies title, impact, description and every standard mapping as tags, so a
  # plain `cinc-auditor exec` (or Heimdall) sees the same metadata as the CLI.
  # Host-scoped controls (kernel, boot chain, firewall, audit subsystem...) are
  # not applicable inside a container: the container shares the host kernel.
  def apply(rule, id)
    c = control(id)
    assume_host = rule.input('sdw_assume_host', value: default('sdw_assume_host'))
    if c['scope'] == 'host' && container? && !assume_host
      rule.only_if("not applicable inside a container (#{container_kind}): this control audits the host kernel/boot/daemons") { false }
    end
    rule.title c['title']
    rule.impact IMPACT.fetch(c['severity'])
    rule.desc c['rationale']
    rule.desc 'check', c['check'] if c['check']
    rule.desc 'fix', c.dig('remediation', 'summary') if c.dig('remediation', 'summary')
    m = c['map'] || {}
    rule.tag severity: c['severity'], pillar: c['pillar'], level: c['level']
    rule.tag nist: m['nist'] || [], nist_800_171: m['nist171'] || []
    rule.tag cis_controls_v8: m['cis'] || [], cis_benchmark: m['cis_benchmark']
    rule.tag anssi_bp028: m['anssi'] || [], pci_dss_v4: m['pci'] || [], stig_srg: m['stig'] || []
    rule.tag remediation: c.dig('remediation', 'auto') ? 'auto' : 'manual'
    c
  end

  def container?
    !container_kind.nil?
  end

  # 'docker', 'podman', 'lxc', 'kubernetes'... or nil on a VM / bare metal.
  def container_kind
    SdwMemo.fetch(:container_kind) do
      kind = nil
      kind = 'docker' if inspec.file('/.dockerenv').exist?
      kind ||= 'podman' if inspec.file('/run/.containerenv').exist?
      unless kind
        env = inspec.command("sh -c #{Shellwords.escape('cat /proc/1/environ 2>/dev/null | tr "\\0" "\\n" | grep -m1 "^container="')}").stdout.to_s.strip
        kind = env.split('=', 2).last unless env.empty?
      end
      unless kind
        cg = inspec.command('cat /proc/1/cgroup 2>/dev/null').stdout.to_s
        kind = 'kubernetes' if cg.include?('kubepods')
        kind ||= 'docker' if cg =~ %r{/docker[/-]}
        kind ||= 'lxc' if cg.include?('/lxc')
      end
      kind
    end
  end

  def to_s
    'Shadow-Armor catalog'
  end
end

# Small shared helpers mixed into the resources below.
module ::SdwHelpers
  # Every probe runs through `sh -c`: with --sudo, InSpec prefixes only the
  # first word with sudo, so globs, pipes and loops would otherwise run
  # unprivileged (and silently see nothing in root-only directories).
  def sh(cmd)
    inspec.command("sh -c #{Shellwords.escape(cmd)}")
  end

  def cmd_ok(cmd)
    r = sh(cmd)
    r.exit_status.zero? ? r.stdout : nil
  end

  def which(bin)
    SdwMemo.fetch([:which, bin]) do
      out = cmd_ok("command -v #{bin} 2>/dev/null || for d in /usr/sbin /sbin /usr/bin /bin /usr/lib/systemd /lib/systemd; do [ -x \"$d/#{bin}\" ] && echo \"$d/#{bin}\" && break; done")
      out && !out.strip.empty? ? out.strip.lines.first.strip : nil
    end
  end

  def read_file(path)
    f = inspec.file(path)
    return nil unless f.exist? && f.file?

    f.content
  end

  def list_dir(dir, glob = '*')
    out = cmd_ok("for f in #{Shellwords.escape(dir)}/#{glob}; do [ -e \"$f\" ] && echo \"$f\"; done 2>/dev/null")
    out ? out.lines.map(&:strip).reject(&:empty?).sort : []
  end

  # Strip comments and blank lines, keep order.
  def meaningful_lines(text)
    return [] unless text

    text.lines.map { |l| l.sub(/(^|\s)#.*$/, '').strip }.reject(&:empty?)
  end
end

# A shell snippet run as one unit (see SdwHelpers#sh), for controls.
class ::SdwSh < Inspec.resource(1)
  name 'sdw_sh'
  desc 'Runs a shell snippet (pipes, globs, loops) entirely under sudo when --sudo is used.'
  example "sdw_sh('cat /etc/rsyslog.d/*.conf | grep -v ^#').stdout"

  include SdwHelpers

  def initialize(cmd)
    @cmd = cmd
  end

  def result
    @result ||= sh(@cmd)
  end

  def stdout
    result.stdout.to_s
  end

  def exit_status
    result.exit_status
  end

  def to_s
    "shell: #{@cmd}"
  end
end
