# frozen_string_literal: true

# Pillar 11 - Chiffrez vos données et les données métier de vos applications
# Data encryption at rest and protection of secrets on disk.

data_mounts = Array(input('sdw_data_mounts', value: sdw_catalog.default('sdw_data_mounts')))
app_dirs = Array(input('sdw_app_data_dirs', value: sdw_catalog.default('sdw_app_data_dirs')))

blk = sdw_block

control 'SA-11.01' do
  sdw_catalog.apply(self, 'SA-11.01')
  only_if('lsblk is not available') { command('lsblk').exist? }
  mounted = data_mounts.select { |m| blk.encryption_of(m).mounted? }
  only_if('none of sdw_data_mounts is mounted') { !mounted.empty? }
  mounted.each do |m|
    enc = blk.encryption_of(m)
    describe enc do
      its('protection') { should be_in %w[crypt tmpfs zram] }
    end
  end
end

control 'SA-11.02' do
  sdw_catalog.apply(self, 'SA-11.02')
  # Swap file: protected when its filesystem sits on dm-crypt.
  file_on_crypt = lambda do |path|
    mp = sdw_sh("df --output=target #{Shellwords.escape(path)} 2>/dev/null | tail -1").stdout.strip
    !mp.empty? && blk.encryption_of(mp).protection == 'crypt'
  end
  live = (file('/proc/swaps').content.to_s.lines.drop(1).map { |l| l.split.first }).compact
  unsafe_now = live.reject do |dev|
    dev.start_with?('/dev/') ? %w[crypt zram].include?(blk.protection_of_device(dev)) : file_on_crypt.call(dev)
  end
  # At boot: the swap entries of /etc/fstab (what systemd-fstab-generator
  # activates). A /dev/mapper name is protected when crypttab opens it.
  crypt_names = blk.crypttab.map { |e| e[:name] }
  by = { 'UUID' => 'by-uuid', 'LABEL' => 'by-label', 'PARTUUID' => 'by-partuuid', 'PARTLABEL' => 'by-partlabel' }
  boot = blk.fstab_swaps
  unsafe_boot = boot.reject do |spec|
    key, val = spec.split('=', 2)
    dev = by[key] && val ? "/dev/disk/#{by[key]}/#{val}" : spec
    if dev.start_with?('/dev/mapper/')
      crypt_names.include?(dev.delete_prefix('/dev/mapper/')) || blk.protection_of_device(dev) == 'crypt'
    elsif dev.start_with?('/dev/')
      dev.start_with?('/dev/zram') || %w[crypt zram].include?(blk.protection_of_device(dev))
    else
      file_on_crypt.call(dev)
    end
  end
  describe SdwState.new("swap areas not backed by dm-crypt or zram (#{live.size} active, #{boot.size} in /etc/fstab)", runtime: unsafe_now, persistent: unsafe_boot) do
    its('runtime') { should be_empty }
    its('persistent') { should be_empty }
  end
end

control 'SA-11.03' do
  sdw_catalog.apply(self, 'SA-11.03')
  luks = blk.devices.select { |_, d| d[:fstype] == 'crypto_LUKS' }.keys.uniq
  only_if('no LUKS volume found') { !luks.empty? }
  only_if('cryptsetup is not installed') { command('cryptsetup').exist? }
  luks.each do |dev|
    dump = sdw_sh("cryptsetup luksDump #{dev} 2>/dev/null").stdout.to_s
    version = dump[/^Version:\s*(\d+)/, 1].to_i
    kdfs = dump.scan(/^\s*PBKDF:\s*(\S+)/).flatten
    describe SdwValue.new("#{dev} LUKS version", version) do
      its('value') { should cmp 2 }
    end
    describe SdwFindings.new("#{dev} key slots not using argon2id/argon2i (PBKDFs: #{kdfs.join(', ')})", kdfs.reject { |k| k.start_with?('argon2') }) do
      its('items') { should be_empty }
    end
  end
end

control 'SA-11.04' do
  sdw_catalog.apply(self, 'SA-11.04')
  in_use = sdw_unit('systemd-coredump.socket').exists? || file('/usr/lib/systemd/systemd-coredump').exist? || file('/lib/systemd/systemd-coredump').exist?
  only_if('systemd-coredump is not installed') { in_use }
  cfg = sdw_systemd.cat_config('systemd/coredump.conf')['Coredump'] || {}
  describe SdwValue.new('systemd-coredump Storage (effective, drop-ins merged; default external)', cfg['Storage'] || 'external') do
    its('value') { should cmp 'none' }
  end
  describe SdwValue.new('systemd-coredump ProcessSizeMax (effective)', cfg['ProcessSizeMax'] || 'default') do
    its('value') { should cmp '0' }
  end
end

control 'SA-11.05' do
  sdw_catalog.apply(self, 'SA-11.05')
  describe SdwFindings.new('private key locations readable by other users', sdw_secrets.private_key_problems) do
    its('items') { should be_empty }
  end
end

control 'SA-11.06' do
  sdw_catalog.apply(self, 'SA-11.06')
  present = app_dirs.select { |d| directory(d).exist? }
  only_if('none of sdw_app_data_dirs exists on this host') { !present.empty? }
  present.each do |d|
    describe sdw_perms(d, max: '0770') do
      its('violations') { should be_empty }
    end
  end
end

control 'SA-11.07' do
  sdw_catalog.apply(self, 'SA-11.07')
  describe SdwFindings.new('user credential files accessible by group/other', sdw_secrets.user_secret_problems) do
    its('items') { should be_empty }
  end
end
