# frozen_string_literal: true

# Listening sockets as the kernel reports them (ss, or /proc/net as fallback).
class ::SdwListen < Inspec.resource(1)
  name 'sdw_listen'
  desc 'Sockets listening right now, with the owning process when readable.'
  example "describe sdw_listen do\n  its('exposed_ports') { should all(be_in [22]) }\nend"

  include SdwHelpers

  LOOPBACK = /\A(127\.|::1\z|\[::1\]|localhost|0000:0000:0000:0000:0000:0000:0000:0001)/

  # [{proto:, addr:, port:, process:}]
  def sockets
    SdwMemo.fetch(:listen) { which('ss') ? from_ss : from_proc }
  end

  # Sockets reachable from the network. A UDP socket on an ephemeral port
  # that belongs to a process is the client side of an exchange (DNS, QUIC,
  # NTP...), not a service: it is left out. Kernel-owned UDP sockets
  # (WireGuard, VXLAN) have no process and stay in.
  def exposed
    procs_known = sockets.any? { |s| s[:process] }
    sockets.reject do |s|
      s[:addr] =~ LOOPBACK || s[:addr].to_s.start_with?('%lo') ||
        (s[:proto] == 'udp' && ephemeral?(s[:port]) && (s[:process] || !procs_known))
    end
  end

  # net.ipv4.ip_local_port_range, the ports the kernel hands out to clients.
  def ephemeral_range
    SdwMemo.fetch(:ephemeral_range) do
      lo, hi = read_file('/proc/sys/net/ipv4/ip_local_port_range').to_s.split.map(&:to_i)
      lo.to_i.positive? && hi.to_i >= lo ? (lo..hi) : (32_768..60_999)
    end
  end

  def ephemeral?(port)
    ephemeral_range.cover?(port.to_i)
  end

  # SMTP submission/relay ports bound beyond loopback, now.
  def runtime_smtp_exposed
    [25, 465, 587].flat_map { |p| ports_bound_beyond_loopback(p) }
  end

  def exposed_ports
    exposed.map { |s| s[:port] }.uniq.sort
  end

  # Human evidence: "tcp 0.0.0.0:25 (master)".
  def exposed_list
    exposed.map { |s| "#{s[:proto]} #{s[:addr]}:#{s[:port]}#{s[:process] ? " (#{s[:process]})" : ''}" }.uniq
  end

  def ports_bound_beyond_loopback(port)
    exposed.select { |s| s[:port] == port.to_i }.map { |s| "#{s[:proto]} #{s[:addr]}:#{s[:port]}" }
  end

  def to_s
    'listening sockets'
  end

  private

  def from_ss
    out = cmd_ok('ss -H -tulnp 2>/dev/null') || cmd_ok('ss -H -tuln 2>/dev/null') || ''
    out.lines.filter_map do |l|
      f = l.split
      next if f.size < 5

      proto = f[0]
      local = f[4]
      addr, _, port = local.rpartition(':')
      addr = addr.delete_prefix('[').delete_suffix(']')
      addr = addr.sub(/%.*\z/, '') unless addr.start_with?('%')
      proc_name = l[/users:\(\("([^"]+)"/, 1]
      { proto: proto, addr: addr, port: port.to_i, process: proc_name }
    end
  end

  def from_proc
    rows = []
    { 'tcp' => ['/proc/net/tcp', '/proc/net/tcp6'], 'udp' => ['/proc/net/udp', '/proc/net/udp6'] }.each do |proto, files|
      files.each do |f|
        (read_file(f) || '').lines.drop(1).each do |l|
          c = l.split
          next unless c[3] == (proto == 'tcp' ? '0A' : '07')

          hex_addr, hex_port = c[1].split(':')
          rows << { proto: proto, addr: decode(hex_addr), port: hex_port.to_i(16), process: nil }
        end
      end
    end
    rows
  end

  def decode(hex)
    if hex.size == 8
      [hex].pack('H*').unpack('C4').reverse.join('.')
    else
      words = [hex].pack('H*').unpack('N4').map { |w| [w].pack('V').unpack1('H*') }
      words.join.scan(/..../).join(':').sub(/\A(0000:){5}ffff:/, '::ffff:')
    end
  end
end

# Host firewall: is a default-deny inbound policy loaded in the kernel now,
# and will one be loaded at boot.
class ::SdwFirewall < Inspec.resource(1)
  name 'sdw_firewall'
  desc 'Inbound filtering policy loaded now (nftables/iptables) and at boot (enabled firewall service).'
  example "describe sdw_firewall do\n  its('runtime_default_deny') { should cmp true }\nend"

  include SdwHelpers

  def runtime_default_deny
    !evidence.empty?
  end

  # Which ruleset proves it: e.g. ["nft inet firewalld filter_INPUT policy drop"].
  def evidence
    SdwMemo.fetch(:fw_evidence) do
      ev = []
      if which('nft')
        out = cmd_ok('nft list ruleset 2>/dev/null').to_s
        table = nil
        chain = nil
        out.each_line do |l|
          table = l.strip if l =~ /\Atable\s/
          chain = l[/chain\s+(\S+)/, 1] if l =~ /\A\s*chain\s/
          if l =~ /type filter hook input .*policy (drop|reject)/
            ev << "nft #{table.to_s.sub(/\s*\{\z/, '')} chain #{chain} policy #{Regexp.last_match(1)}"
          end
        end
        # firewalld / ufw on nft often keep policy accept but end the chain with a reject rule.
        if ev.empty? && out =~ /hook input.*\n(?:.*\n)*?\s*(reject|drop)\s*(with .*)?\n\s*\}/
          ev << 'nft input chain terminated by a catch-all reject/drop rule'
        end
      end
      if ev.empty? && which('iptables')
        out = cmd_ok('iptables -S INPUT 2>/dev/null').to_s
        ev << 'iptables INPUT policy DROP' if out =~ /\A-P INPUT DROP/
        ev << 'iptables INPUT ends with REJECT/DROP' if ev.empty? && out.lines.last.to_s =~ /\A-A INPUT -j (REJECT|DROP)/
      end
      if ev.empty? && which('ufw')
        out = cmd_ok('ufw status verbose 2>/dev/null').to_s
        ev << 'ufw active, default deny (incoming)' if out =~ /Status: active/ && out =~ /Default: (deny|reject) \(incoming\)/
      end
      ev
    end
  end

  # A firewall service that restores a policy at boot.
  def persistent_enabled
    !persistent_service.nil?
  end

  def persistent_service
    SdwMemo.fetch(:fw_service) do
      found = nil
      %w[firewalld.service ufw.service nftables.service netfilter-persistent.service iptables.service].each do |u|
        st = sh("systemctl is-enabled #{u} 2>/dev/null").stdout.to_s.strip
        if st == 'enabled'
          if u == 'ufw.service'
            conf = read_file('/etc/ufw/ufw.conf').to_s
            next unless conf =~ /^\s*ENABLED\s*=\s*yes/
          end
          found = u
          break
        end
      end
      found
    end
  end

  def to_s
    'host firewall'
  end
end
