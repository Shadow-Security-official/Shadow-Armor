# frozen_string_literal: true

# Pillar 15 - Maîtrisez le matériel, le microcode et le firmware
# Hardware & firmware.

hw = sdw_hardware

physical_only = lambda do
  only_if("not applicable in a virtual machine (#{hw.virtual}): the hypervisor owns this hardware") { !hw.virtual? }
end

# Packages that ship the microcode of each vendor (Debian/Ubuntu, RHEL-family,
# SUSE, Arch).
microcode = {
  'intel' => %w[intel-microcode microcode_ctl ucode-intel intel-ucode],
  'amd' => %w[amd64-microcode linux-firmware amd-ucode-firmware ucode-amd amd-ucode],
}

control 'SA-15.01' do
  sdw_catalog.apply(self, 'SA-15.01')
  only_if('the kernel reports no CPU vulnerability status (/sys/devices/system/cpu/vulnerabilities)') { hw.cpu_vulns_readable? }
  describe hw do
    its('vulnerable_flaws') { should be_empty }
    its('runtime_mitigations_off') { should be_empty }
    its('persistent_mitigations_off') { should be_empty }
  end
end

control 'SA-15.02' do
  sdw_catalog.apply(self, 'SA-15.02')
  instance_exec(&physical_only)
  only_if('the CPU has no SMT (hyper-threading) to turn off') { hw.smt_capable? }
  describe hw do
    its('runtime_smt_exposed') { should be_empty }
    its('persistent_smt_exposed') { should be_empty }
  end
end

control 'SA-15.03' do
  sdw_catalog.apply(self, 'SA-15.03')
  instance_exec(&physical_only)
  only_if('not an x86 CPU from Intel or AMD (microcode comes with the firmware)') { hw.x86? && !hw.cpu_vendor.nil? }
  only_if('no package database found (dpkg/rpm/apk)') { !sdw_packages.manager.nil? }
  candidates = microcode.fetch(hw.cpu_vendor.to_s, [])
  describe SdwFindings.new("#{hw.cpu_vendor} microcode packages installed among #{candidates.join(', ')}", sdw_packages.installed(candidates)) do
    its('items') { should_not be_empty }
  end
end

control 'SA-15.04' do
  sdw_catalog.apply(self, 'SA-15.04')
  instance_exec(&physical_only)
  describe hw do
    its('runtime_iommu_active') { should cmp true }
    its('persistent_iommu_enabled') { should cmp true }
  end
end

control 'SA-15.05' do
  sdw_catalog.apply(self, 'SA-15.05')
  only_if('no Thunderbolt controller') { !hw.thunderbolt_domains.empty? }
  describe hw do
    its('thunderbolt_insecure') { should be_empty }
  end
end

control 'SA-15.06' do
  sdw_catalog.apply(self, 'SA-15.06')
  sdw_catalog.control('SA-15.06')['remediation']['actions'][0]['modules'].each do |m|
    describe sdw_kmod(m) do
      its('runtime_loaded') { should cmp false }
      its('persistent_disabled') { should cmp true }
    end
  end
end

control 'SA-15.07' do
  sdw_catalog.apply(self, 'SA-15.07')
  describe SdwValue.new('TPM major version (/sys/class/tpm)', hw.tpm_version) do
    its('value') { should cmp 2 }
  end
end

control 'SA-15.08' do
  sdw_catalog.apply(self, 'SA-15.08')
  only_if('no BMC device (/dev/ipmi0)') { hw.bmc? }
  describe hw do
    its('ipmi_weak_lan') { should be_empty }
  end
end

control 'SA-15.09' do
  sdw_catalog.apply(self, 'SA-15.09')
  instance_exec(&physical_only)
  only_if('fwupd is not installed (firmware follows the vendor tools)') { hw.fwupd? }
  describe hw do
    its('firmware_updates') { should be_empty }
  end
end

control 'SA-15.10' do
  sdw_catalog.apply(self, 'SA-15.10')
  instance_exec(&physical_only)
  describe hw do
    its('usbguard_policy_gaps') { should be_empty }
    its('runtime_usbguard_active') { should cmp true }
    its('persistent_usbguard_enabled') { should cmp true }
  end
end
