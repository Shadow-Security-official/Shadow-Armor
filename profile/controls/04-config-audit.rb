# frozen_string_literal: true

# Pillar 4 - Auditez vos configurations serveurs
# Server configuration integrity.

fs_scan = input('sdw_fs_scan', value: sdw_catalog.default('sdw_fs_scan'))

perms = lambda do |glob, max, owner = 'root', groups = nil|
  describe sdw_perms(glob, max: max, owner: owner, groups: groups) do
    its('violations') { should be_empty }
  end
end

control 'SA-04.01' do
  sdw_catalog.apply(self, 'SA-04.01')
  describe sdw_fim do
    its('installed') { should cmp true }
    its('database') { should_not be_nil }
  end
end

control 'SA-04.02' do
  sdw_catalog.apply(self, 'SA-04.02')
  describe sdw_fim do
    its('schedule') { should_not be_nil }
  end
end

control 'SA-04.03' do
  sdw_catalog.apply(self, 'SA-04.03')
  instance_exec('/etc/passwd', '0644', &perms)
  instance_exec('/etc/group', '0644', &perms)
end

control 'SA-04.04' do
  sdw_catalog.apply(self, 'SA-04.04')
  instance_exec('/etc/shadow', '0640', 'root', %w[root shadow], &perms)
  instance_exec('/etc/gshadow', '0640', 'root', %w[root shadow], &perms)
end

control 'SA-04.05' do
  sdw_catalog.apply(self, 'SA-04.05')
  instance_exec('/etc/passwd-', '0644', &perms)
  instance_exec('/etc/group-', '0644', &perms)
  instance_exec('/etc/shadow-', '0640', 'root', %w[root shadow], &perms)
  instance_exec('/etc/gshadow-', '0640', 'root', %w[root shadow], &perms)
end

control 'SA-04.06' do
  sdw_catalog.apply(self, 'SA-04.06')
  cfgs = sdw_boot.grub_configs
  only_if('no GRUB configuration found (other boot loader or container)') { !cfgs.empty? }
  cfgs.each { |g| instance_exec(g, '0600', &perms) }
end

control 'SA-04.07' do
  sdw_catalog.apply(self, 'SA-04.07')
  only_if('no GRUB configuration found (other boot loader or container)') { !sdw_boot.grub_configs.empty? }
  describe sdw_boot do
    its('grub_password') { should cmp true }
  end
end

control 'SA-04.08' do
  sdw_catalog.apply(self, 'SA-04.08')
  only_if('cron is not installed') { file('/etc/crontab').exist? || directory('/etc/cron.d').exist? }
  instance_exec('/etc/crontab', '0600', &perms)
  %w[/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly].each do |d|
    instance_exec(d, '0700', &perms)
  end
end

control 'SA-04.09' do
  sdw_catalog.apply(self, 'SA-04.09')
  only_if('cron is not installed') { file('/etc/crontab').exist? || directory('/etc/cron.d').exist? }
  describe file('/etc/cron.allow') do
    it { should exist }
  end
  instance_exec('/etc/cron.allow', '0640', &perms)
  if command('at').exist?
    describe file('/etc/at.allow') do
      it { should exist }
    end
  end
end

control 'SA-04.10' do
  sdw_catalog.apply(self, 'SA-04.10')
  only_if('not booted in UEFI mode') { sdw_boot.efi? }
  describe sdw_boot do
    its('secure_boot') { should cmp true }
  end
end

control 'SA-04.11' do
  sdw_catalog.apply(self, 'SA-04.11')
  only_if('the kernel has no lockdown LSM') { file('/sys/kernel/security/lockdown').exist? }
  boot = sdw_boot
  param = sdw_cmdline('lockdown')
  # Mode of the next boot: lockdown= on the boot command line, a kernel built
  # to force it, or a kernel that locks down when Secure Boot is on.
  kconf = sdw_sh('cat "/boot/config-$(uname -r)" 2>/dev/null').stdout.to_s
  forced = kconf[/^CONFIG_LOCK_DOWN_KERNEL_FORCE_(INTEGRITY|CONFIDENTIALITY)=y/, 1]&.downcase
  by_sb = kconf.match?(/^CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y/) && boot.efi? && boot.secure_boot
  next_boot, why = if %w[integrity confidentiality].include?(param.persistent.to_s)
                     [param.persistent, "lockdown=#{param.persistent} in #{param.persistent_origin}"]
                   elsif forced
                     [forced, 'forced by the kernel configuration']
                   elsif by_sb
                     ['integrity', 'Secure Boot is enabled and the kernel locks down under it']
                   else
                     ['none', 'no lockdown= parameter, no Secure Boot lockdown']
                   end
  describe SdwState.new("kernel lockdown (live: #{boot.lockdown}; next boot: #{why})", runtime: boot.lockdown, persistent: next_boot) do
    its('runtime') { should be_in %w[integrity confidentiality] }
    its('persistent') { should be_in %w[integrity confidentiality] }
  end
end

control 'SA-04.12' do
  sdw_catalog.apply(self, 'SA-04.12')
  only_if('filesystem scan disabled (sdw_fs_scan: false)') { fs_scan }
  describe sdw_fs_scan do
    its('world_writable_files') { should be_empty }
  end
end

control 'SA-04.13' do
  sdw_catalog.apply(self, 'SA-04.13')
  only_if('filesystem scan disabled (sdw_fs_scan: false)') { fs_scan }
  describe sdw_fs_scan do
    its('world_writable_dirs_without_sticky') { should be_empty }
  end
end

control 'SA-04.14' do
  sdw_catalog.apply(self, 'SA-04.14')
  only_if('filesystem scan disabled (sdw_fs_scan: false)') { fs_scan }
  describe sdw_fs_scan do
    its('unowned') { should be_empty }
  end
end
