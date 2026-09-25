# frozen_string_literal: true

# Pillar 10 - Vérifiez les mises à jour applicatives
# Updates & patching. Read-only: the audit never refreshes metadata or installs.

max_age = input('sdw_metadata_max_age_days', value: sdw_catalog.default('sdw_metadata_max_age_days')).to_f
eol_table = input('sdw_eol', value: sdw_catalog.default('sdw_eol'))

upd = sdw_updates
no_pm = 'no supported package manager (apt, dnf, yum, zypper)'

control 'SA-10.01' do
  sdw_catalog.apply(self, 'SA-10.01')
  only_if(no_pm) { !upd.family.nil? }
  describe upd do
    its('pending_security') { should be_empty }
  end
end

control 'SA-10.02' do
  sdw_catalog.apply(self, 'SA-10.02')
  only_if(no_pm) { !upd.family.nil? }
  describe SdwValue.new("age in days of the newest package metadata (#{upd.family})", upd.metadata_age_days) do
    its('value') { should_not be_nil }
    its('value') { should cmp <= max_age }
  end
end

control 'SA-10.03' do
  sdw_catalog.apply(self, 'SA-10.03')
  only_if(no_pm) { !upd.family.nil? }
  describe upd.automatic_updates do
    its('persistent') { should cmp true }
  end
end

control 'SA-10.04' do
  sdw_catalog.apply(self, 'SA-10.04')
  only_if(no_pm) { !upd.family.nil? }
  problems = []
  case upd.family
  when :apt
    sources = sdw_sh("cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null | grep -vE '^\\s*#'").stdout.to_s
    problems << 'apt source with [trusted=yes] / Trusted: yes' if sources =~ /trusted\s*=\s*yes|^Trusted:\s*yes/i
    cfg = sdw_sh('apt-config dump 2>/dev/null').stdout.to_s
    %w[APT::Get::AllowUnauthenticated Acquire::AllowInsecureRepositories Acquire::AllowDowngradeToInsecureRepositories].each do |k|
      problems << "#{k} enabled (apt-config dump)" if cfg =~ /^#{Regexp.escape(k)} "(1|true|yes)";/i
    end
  when :dnf, :yum
    main = sdw_kv('/etc/dnf/dnf.conf', sep: '=', section: 'main').value('gpgcheck') || sdw_kv('/etc/yum.conf', sep: '=', section: 'main').value('gpgcheck')
    problems << "gpgcheck=#{main || 'unset'} in [main]" unless %w[1 True true yes].include?(main.to_s)
    repos = sdw_sh("grep -HisE '^\\s*gpgcheck\\s*=\\s*(0|false|no)' /etc/yum.repos.d/*.repo 2>/dev/null").stdout.to_s
    problems.concat(repos.lines.map { |l| "repository with #{l.strip}" })
  end
  describe SdwFindings.new('package signature verification weaknesses', problems) do
    its('items') { should be_empty }
  end
end

control 'SA-10.05' do
  sdw_catalog.apply(self, 'SA-10.05')
  only_if('no kernel package installed in this system image') { upd.kernel_installed? }
  newest = upd.persistent_kernel
  describe upd do
    # runtime: the kernel running now; persistent: what the next boot runs.
    its('runtime_kernel') { should cmp newest }
    its('persistent_kernel') { should_not be_nil }
  end
end

control 'SA-10.06' do
  sdw_catalog.apply(self, 'SA-10.06')
  describe upd do
    its('processes_with_deleted_libs') { should be_empty }
  end
end

control 'SA-10.07' do
  sdw_catalog.apply(self, 'SA-10.07')
  os_r = sdw_os
  days = os_r.days_until_eol(eol_table)
  only_if("#{os_r} is not in the sdw_eol table") { !days.nil? }
  describe SdwValue.new("days until end of standard support of #{os_r} (#{os_r.eol_date(eol_table)})", days) do
    its('value') { should cmp > 0 }
  end
end
