# frozen_string_literal: true

# Pillar 5 - Activez les logs, première étape vers la conformité
# Logging & audit trail.

systemd_up = sdw_systemd.running?
auditd = sdw_auditd

running_and_enabled = lambda do |label, units|
  describe sdw_service_set(label, units) do
    its('runtime_any_active') { should cmp true } if systemd_up
    its('persistent_any_enabled') { should cmp true }
  end
end

# The rules of an audit control come from its catalog remediation, so the
# check verifies exactly what `sdw-armor harden` would install.
audit_rules = lambda do |id|
  only_if('auditd is not installed (see SA-05.03)') { auditd.installed? }
  rules = sdw_catalog.control(id)['remediation']['actions'][0]['rules']
  rules.each do |r|
    check = if (m = r.match(/-w\s+(\S+)\s+-p\s+(\w+)/))
              auditd.watch(m[1], m[2])
            else
              arch = r[/arch=(b\d\d)/, 1]
              next if arch == 'b32' && os.arch.to_s != 'x86_64'

              names = r.scan(/-S\s+(\S+)/).flatten.flat_map { |s| s.split(',') }
              extra = r.include?('euid!=uid') ? /euid!=uid|uid!=euid/ : nil
              auditd.syscalls(names, arch: arch, extra: extra)
            end
    describe check do
      its('runtime') { should cmp true }
      its('persistent') { should cmp true }
    end
  end
end

control 'SA-05.01' do
  sdw_catalog.apply(self, 'SA-05.01')
  instance_exec('system logger', %w[systemd-journald.service rsyslog.service syslog-ng.service], &running_and_enabled)
end

control 'SA-05.02' do
  sdw_catalog.apply(self, 'SA-05.02')
  only_if('systemd-journald is not in use') { sdw_unit('systemd-journald.service').exists? }
  storage = sdw_systemd.cat_config('systemd/journald.conf').dig('Journal', 'Storage') || 'auto'
  persistent = storage == 'persistent' || (storage == 'auto' && directory('/var/log/journal').exist?)
  describe SdwValue.new("journald Storage=#{storage} (effective, drop-ins merged; /var/log/journal #{directory('/var/log/journal').exist? ? 'present' : 'absent'})", persistent) do
    its('value') { should cmp true }
  end
end

control 'SA-05.03' do
  sdw_catalog.apply(self, 'SA-05.03')
  describe SdwValue.new('auditd installed (auditctl present)', auditd.installed?) do
    its('value') { should cmp true }
  end
  instance_exec('audit daemon', %w[auditd.service], &running_and_enabled)
end

control 'SA-05.04' do
  sdw_catalog.apply(self, 'SA-05.04')
  describe sdw_cmdline('audit') do
    its('runtime') { should cmp '1' }
    its('persistent') { should cmp '1' }
  end
end

control 'SA-05.05' do
  sdw_catalog.apply(self, 'SA-05.05')
  describe sdw_cmdline('audit_backlog_limit') do
    its('runtime') { should cmp >= 8192 }
    its('persistent') { should cmp >= 8192 }
  end
end

control 'SA-05.06' do
  sdw_catalog.apply(self, 'SA-05.06')
  instance_exec('SA-05.06', &audit_rules)
end

control 'SA-05.07' do
  sdw_catalog.apply(self, 'SA-05.07')
  instance_exec('SA-05.07', &audit_rules)
end

control 'SA-05.08' do
  sdw_catalog.apply(self, 'SA-05.08')
  instance_exec('SA-05.08', &audit_rules)
end

control 'SA-05.09' do
  sdw_catalog.apply(self, 'SA-05.09')
  instance_exec('SA-05.09', &audit_rules)
end

control 'SA-05.10' do
  sdw_catalog.apply(self, 'SA-05.10')
  instance_exec('SA-05.10', &audit_rules)
end

control 'SA-05.11' do
  sdw_catalog.apply(self, 'SA-05.11')
  instance_exec('SA-05.11', &audit_rules)
end

control 'SA-05.12' do
  sdw_catalog.apply(self, 'SA-05.12')
  instance_exec('SA-05.12', &audit_rules)
end

control 'SA-05.13' do
  sdw_catalog.apply(self, 'SA-05.13')
  only_if('auditd is not installed (see SA-05.03)') { auditd.installed? }
  describe auditd.immutable do
    its('runtime') { should cmp true }
    its('persistent') { should cmp true }
  end
end

control 'SA-05.14' do
  sdw_catalog.apply(self, 'SA-05.14')
  only_if('auditd is not installed (see SA-05.03)') { auditd.installed? }
  conf = sdw_kv('/etc/audit/auditd.conf', sep: '=', casefold: true)
  {
    'max_log_file_action' => %w[keep_logs rotate],
    'space_left_action' => %w[email exec single halt],
    'admin_space_left_action' => %w[single halt],
    'disk_full_action' => %w[single halt],
  }.each do |k, ok|
    describe conf.setting(k) do
      its('value') { should be_in(ok + ok.map(&:upcase)) }
    end
  end
end

control 'SA-05.15' do
  sdw_catalog.apply(self, 'SA-05.15')
  only_if('auditd is not installed (see SA-05.03)') { auditd.installed? }
  logfile = sdw_kv('/etc/audit/auditd.conf', sep: '=', casefold: true).value('log_file') || '/var/log/audit/audit.log'
  dir = File.dirname(logfile)
  describe sdw_perms(dir, max: '0750', owner: 'root') do
    its('violations') { should be_empty }
  end
  describe sdw_perms("#{dir}/*", max: '0640', owner: 'root') do
    its('violations') { should be_empty }
  end
end

control 'SA-05.16' do
  sdw_catalog.apply(self, 'SA-05.16')
  rsyslog = sdw_sh("cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -vE '^\\s*#'").stdout.to_s
  syslogng = sdw_sh("cat /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf 2>/dev/null | grep -vE '^\\s*#'").stdout.to_s
  forwards = []
  forwards << 'rsyslog omfwd' if rsyslog =~ /type\s*=\s*"omfwd"/
  forwards << 'rsyslog @host' if rsyslog =~ /^\s*[^\s#$]\S*\s+@@?[\w\[\].:-]+/
  forwards << 'syslog-ng network destination' if syslogng =~ /destination\s+\w+\s*\{\s*(network|tcp|udp|syslog)\s*\(/
  forwards << 'systemd-journal-upload' if sdw_unit('systemd-journal-upload.service').persistent_enabled
  describe SdwFindings.new('remote log forwarding (rsyslog, syslog-ng, systemd-journal-upload)', forwards) do
    its('items') { should_not be_empty }
  end
end

control 'SA-05.17' do
  sdw_catalog.apply(self, 'SA-05.17')
  instance_exec('time synchronisation', %w[chrony.service chronyd.service systemd-timesyncd.service ntp.service ntpd.service ntpsec.service openntpd.service], &running_and_enabled)
end
