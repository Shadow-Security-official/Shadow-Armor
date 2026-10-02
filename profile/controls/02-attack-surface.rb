# frozen_string_literal: true

# Pillar 2 - Réduisez la surface d'attaque : désactivez les services non essentiels
# Attack surface & non-essential services.

allowed_ports = Array(input('sdw_allowed_listening_ports', value: sdw_catalog.default('sdw_allowed_listening_ports'))).map(&:to_i)
systemd_up = sdw_systemd.running?

# Helpers are lambdas run with instance_exec inside each control, so their
# describe blocks attach to that control.
# Units that must be neither running nor enabled; packages that must be absent.
disabled_units = lambda do |label, units, packages = []|
  describe sdw_service_set(label, units) do
    its('runtime_active') { should be_empty } if systemd_up
    its('persistent_enabled') { should be_empty }
  end
  next if packages.empty?

  describe SdwFindings.new("installed packages among #{packages.join(', ')}", sdw_packages.installed(packages)) do
    its('items') { should be_empty }
  end
end

sysctl_all = lambda do |settings, absent_ok = false|
  settings.each do |k, v|
    describe sdw_sysctl(k, absent_ok: absent_ok) do
      its('runtime') { should cmp v }
      its('persistent') { should cmp v }
    end
  end
end

module_unavailable = lambda do |mods|
  mods.each do |m|
    describe sdw_kmod(m) do
      its('runtime_loaded') { should cmp false }
      its('persistent_disabled') { should cmp true }
    end
  end
end

# A separate mount with the options, now and at boot. Options are only
# asserted where the mount exists, so a missing mount reports once.
mount_hardened = lambda do |path, opts|
  m = sdw_mount(path)
  describe m do
    its('runtime_mounted') { should cmp true }
    its('persistent_mounted') { should cmp true }
    its('runtime_options') { should include(*opts) } if m.runtime_mounted
    its('persistent_options') { should include(*opts) } if m.persistent_mounted
  end
end

control 'SA-02.01' do
  sdw_catalog.apply(self, 'SA-02.01')
  c = sdw_catalog.control('SA-02.01')
  acts = c['remediation']['actions']
  instance_exec('legacy remote access services', acts[0]['units'], acts[1]['packages'], &disabled_units)
end

control 'SA-02.02' do
  sdw_catalog.apply(self, 'SA-02.02')
  instance_exec('Avahi mDNS', %w[avahi-daemon.service avahi-daemon.socket], &disabled_units)
end

control 'SA-02.03' do
  sdw_catalog.apply(self, 'SA-02.03')
  instance_exec('CUPS print server', %w[cups.service cups.socket cups.path cups-browsed.service], &disabled_units)
end

control 'SA-02.04' do
  sdw_catalog.apply(self, 'SA-02.04')
  describe sdw_listen do
    it "exposes only the allowed ports (#{allowed_ports.join(', ')})" do
      expect(subject.exposed.reject { |s| allowed_ports.include?(s[:port]) }.map { |s| "#{s[:proto]} #{s[:addr]}:#{s[:port]}#{s[:process] ? " (#{s[:process]})" : ''}" }.uniq).to eq []
    end
  end
end

control 'SA-02.05' do
  sdw_catalog.apply(self, 'SA-02.05')
  instance_exec('NFS/RPC services', %w[rpcbind.service rpcbind.socket nfs-server.service nfs-kernel-server.service], &disabled_units)
end

control 'SA-02.06' do
  sdw_catalog.apply(self, 'SA-02.06')
  instance_exec('SNMP daemon', %w[snmpd.service], &disabled_units)
end

control 'SA-02.07' do
  sdw_catalog.apply(self, 'SA-02.07')
  mtas = sdw_packages.installed(%w[postfix exim4-daemon-light exim4-daemon-heavy exim sendmail sendmail-bin opensmtpd courier-mta])
  if mtas.empty? && !sdw_packages.manager.nil?
    # No MTA installed: nothing can listen on SMTP, now or after a reboot.
    describe SdwFindings.new('installed mail transfer agents (postfix, exim, sendmail, opensmtpd, courier)', mtas) do
      its('items') { should be_empty }
    end
  else
    describe sdw_listen do
      its('runtime_smtp_exposed') { should be_empty }
    end
  end
end

control 'SA-02.08' do
  sdw_catalog.apply(self, 'SA-02.08')
  instance_exec(%w[cramfs freevxfs hfs hfsplus jffs2 udf], &module_unavailable)
end

control 'SA-02.09' do
  sdw_catalog.apply(self, 'SA-02.09')
  instance_exec(%w[dccp sctp rds tipc], &module_unavailable)
end

control 'SA-02.10' do
  sdw_catalog.apply(self, 'SA-02.10')
  instance_exec(%w[usb-storage], &module_unavailable)
end

control 'SA-02.11' do
  sdw_catalog.apply(self, 'SA-02.11')
  instance_exec({ 'net.ipv4.ip_forward' => 0 }, &sysctl_all)
  instance_exec({ 'net.ipv6.conf.all.forwarding' => 0 }, true, &sysctl_all)
end

control 'SA-02.12' do
  sdw_catalog.apply(self, 'SA-02.12')
  s = sdw_catalog.control('SA-02.12')['remediation']['actions'][0]['settings']
  instance_exec(s.reject { |k, _| k.include?('ipv6') }, &sysctl_all)
  instance_exec(s.select { |k, _| k.include?('ipv6') }, true, &sysctl_all)
end

control 'SA-02.13' do
  sdw_catalog.apply(self, 'SA-02.13')
  s = sdw_catalog.control('SA-02.13')['remediation']['actions'][0]['settings']
  instance_exec(s.reject { |k, _| k.include?('ipv6') }, &sysctl_all)
  instance_exec(s.select { |k, _| k.include?('ipv6') }, true, &sysctl_all)
end

control 'SA-02.14' do
  sdw_catalog.apply(self, 'SA-02.14')
  instance_exec({ 'net.ipv4.conf.all.rp_filter' => 1, 'net.ipv4.conf.default.rp_filter' => 1 }, &sysctl_all)
end

control 'SA-02.15' do
  sdw_catalog.apply(self, 'SA-02.15')
  instance_exec({ 'net.ipv4.tcp_syncookies' => 1 }, &sysctl_all)
end

control 'SA-02.16' do
  sdw_catalog.apply(self, 'SA-02.16')
  instance_exec({ 'net.ipv4.icmp_echo_ignore_broadcasts' => 1, 'net.ipv4.icmp_ignore_bogus_error_responses' => 1 }, &sysctl_all)
end

control 'SA-02.17' do
  sdw_catalog.apply(self, 'SA-02.17')
  instance_exec({ 'net.ipv4.conf.all.log_martians' => 1, 'net.ipv4.conf.default.log_martians' => 1 }, &sysctl_all)
end

control 'SA-02.18' do
  sdw_catalog.apply(self, 'SA-02.18')
  instance_exec({ 'net.ipv6.conf.all.accept_ra' => 0, 'net.ipv6.conf.default.accept_ra' => 0 }, true, &sysctl_all)
end

control 'SA-02.19' do
  sdw_catalog.apply(self, 'SA-02.19')
  describe sdw_firewall do
    its('runtime_default_deny') { should cmp true }
    its('persistent_enabled') { should cmp true }
  end
end

control 'SA-02.20' do
  sdw_catalog.apply(self, 'SA-02.20')
  instance_exec('/tmp', %w[nodev nosuid noexec], &mount_hardened)
end

control 'SA-02.21' do
  sdw_catalog.apply(self, 'SA-02.21')
  instance_exec('/dev/shm', %w[nodev nosuid noexec], &mount_hardened)
end

control 'SA-02.22' do
  sdw_catalog.apply(self, 'SA-02.22')
  instance_exec('/var/tmp', %w[nodev nosuid noexec], &mount_hardened)
end

control 'SA-02.23' do
  sdw_catalog.apply(self, 'SA-02.23')
  instance_exec('automounter', %w[autofs.service], &disabled_units)
end

control 'SA-02.24' do
  sdw_catalog.apply(self, 'SA-02.24')
  unit = sdw_unit('ctrl-alt-del.target')
  describe unit do
    its('runtime_active') { should cmp false } if systemd_up
    it('is masked') { expect(subject.masked? || !subject.exists?).to eq true }
  end
end

control 'SA-02.25' do
  sdw_catalog.apply(self, 'SA-02.25')
  pkgs = sdw_catalog.control('SA-02.25')['remediation']['actions'][0]['packages']
  x = sdw_packages.all.keys.select { |n| n.start_with?('xserver-xorg-core', 'xorg-x11-server-Xorg') } | sdw_packages.installed(pkgs - %w[xwayland xorg-x11-server-Xwayland])
  describe SdwFindings.new('installed X11 display server packages', x) do
    its('items') { should be_empty }
  end
end
