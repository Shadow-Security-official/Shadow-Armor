# frozen_string_literal: true

# Pillar 3 - Supprimez les clients applicatifs à risque
# Risky application clients.

# Every control of this pillar removes packages; the package list lives in the
# catalog remediation so the check and the fix can never drift apart.
# (Control ids stay literal: `cinc-auditor check` parses them statically.)
absent_packages = lambda do |id|
  pkgs = sdw_catalog.control(id)['remediation']['actions'].find { |a| a['kind'] == 'packages_absent' }['packages']
  describe SdwFindings.new("installed packages among #{pkgs.join(', ')}", sdw_packages.installed(pkgs)) do
    its('items') { should be_empty }
  end
end

control 'SA-03.01' do
  sdw_catalog.apply(self, 'SA-03.01')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.01', &absent_packages)
end

control 'SA-03.02' do
  sdw_catalog.apply(self, 'SA-03.02')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.02', &absent_packages)
end

control 'SA-03.03' do
  sdw_catalog.apply(self, 'SA-03.03')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.03', &absent_packages)
end

control 'SA-03.04' do
  sdw_catalog.apply(self, 'SA-03.04')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.04', &absent_packages)
end

control 'SA-03.05' do
  sdw_catalog.apply(self, 'SA-03.05')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.05', &absent_packages)
end

control 'SA-03.06' do
  sdw_catalog.apply(self, 'SA-03.06')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.06', &absent_packages)
end

control 'SA-03.07' do
  sdw_catalog.apply(self, 'SA-03.07')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.07', &absent_packages)
end

control 'SA-03.08' do
  sdw_catalog.apply(self, 'SA-03.08')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.08', &absent_packages)
end

control 'SA-03.09' do
  sdw_catalog.apply(self, 'SA-03.09')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.09', &absent_packages)
end

control 'SA-03.10' do
  sdw_catalog.apply(self, 'SA-03.10')
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  instance_exec('SA-03.10', &absent_packages)
end

control 'SA-03.11' do
  sdw_catalog.apply(self, 'SA-03.11')
  only_if('OpenSSH client is not installed') { command('ssh').exist? }
  # `ssh -G` prints the configuration the client would use for that host,
  # after every Include/Match of /etc/ssh/ssh_config is resolved. No
  # connection is made.
  cfg = sdw_sh('ssh -G sdw-armor.invalid 2>/dev/null').stdout.to_s.lines.to_h { |l| k, v = l.strip.split(/\s+/, 2); [k, v] }
  %w[forwardagent forwardx11].each do |k|
    describe SdwValue.new("ssh -G #{k} (effective client configuration)", cfg[k]) do
      its('value') { should cmp 'no' }
    end
  end
end
