# frozen_string_literal: true

# Pillar 1 - Contrôlez la sécurité et limitez les droits applicatifs
# Application security & least privilege.

exposure_max = input('sdw_max_service_exposure', value: sdw_catalog.default('sdw_max_service_exposure'))
sandbox_exempt = input('sdw_sandbox_exempt_units', value: sdw_catalog.default('sdw_sandbox_exempt_units'))

control 'SA-01.01' do
  sdw_catalog.apply(self, 'SA-01.01')
  describe sdw_mac do
    its('framework') { should_not be_nil }
    its('runtime_enforcing') { should cmp true }
    its('persistent_enforcing') { should cmp true }
  end
end

control 'SA-01.02' do
  sdw_catalog.apply(self, 'SA-01.02')
  describe sdw_sysctl('kernel.randomize_va_space') do
    its('runtime') { should cmp 2 }
    its('persistent') { should cmp 2 }
  end
end

control 'SA-01.03' do
  sdw_catalog.apply(self, 'SA-01.03')
  describe sdw_sysctl('kernel.yama.ptrace_scope') do
    its('runtime') { should cmp >= 1 }
    its('persistent') { should cmp >= 1 }
  end
end

control 'SA-01.04' do
  sdw_catalog.apply(self, 'SA-01.04')
  describe sdw_sysctl('kernel.kptr_restrict') do
    its('runtime') { should cmp >= 1 }
    its('persistent') { should cmp >= 1 }
  end
end

control 'SA-01.05' do
  sdw_catalog.apply(self, 'SA-01.05')
  describe sdw_sysctl('kernel.dmesg_restrict') do
    its('runtime') { should cmp 1 }
    its('persistent') { should cmp 1 }
  end
end

control 'SA-01.06' do
  sdw_catalog.apply(self, 'SA-01.06')
  describe sdw_sysctl('kernel.unprivileged_bpf_disabled', absent_ok: true) do
    its('runtime') { should cmp >= 1 }
    its('persistent') { should cmp >= 1 }
  end
end

control 'SA-01.07' do
  sdw_catalog.apply(self, 'SA-01.07')
  describe sdw_sysctl('kernel.perf_event_paranoid', absent_ok: true) do
    its('runtime') { should cmp >= 2 }
    its('persistent') { should cmp >= 2 }
  end
end

control 'SA-01.08' do
  sdw_catalog.apply(self, 'SA-01.08')
  %w[fs.protected_symlinks fs.protected_hardlinks].each do |k|
    describe sdw_sysctl(k) do
      its('runtime') { should cmp 1 }
      its('persistent') { should cmp 1 }
    end
  end
end

control 'SA-01.09' do
  sdw_catalog.apply(self, 'SA-01.09')
  %w[fs.protected_fifos fs.protected_regular].each do |k|
    describe sdw_sysctl(k) do
      its('runtime') { should cmp 2 }
      its('persistent') { should cmp 2 }
    end
  end
end

control 'SA-01.10' do
  sdw_catalog.apply(self, 'SA-01.10')
  describe sdw_sysctl('fs.suid_dumpable') do
    its('runtime') { should cmp 0 }
    its('persistent') { should cmp 0 }
  end
  describe sdw_limits do
    its('effective_hard_core') { should cmp 0 }
  end
end

control 'SA-01.11' do
  sdw_catalog.apply(self, 'SA-01.11')
  describe sdw_sysctl('kernel.kexec_load_disabled', absent_ok: true) do
    its('runtime') { should cmp 1 }
    its('persistent') { should cmp 1 }
  end
end

control 'SA-01.12' do
  sdw_catalog.apply(self, 'SA-01.12')
  describe sdw_sysctl('kernel.sysrq', absent_ok: true) do
    its('runtime') { should cmp 0 }
    its('persistent') { should cmp 0 }
  end
end

control 'SA-01.13' do
  sdw_catalog.apply(self, 'SA-01.13')
  only_if('systemd is not the running init (no unit sandboxing to evaluate)') { sdw_systemd.running? }
  describe sdw_sandbox do
    it 'exposes no network-facing unit above the allowed exposure' do
      expect(subject.unsafe_exposed_services(exposure_max.to_f, Array(sandbox_exempt))).to eq []
    end
  end
end

control 'SA-01.14' do
  sdw_catalog.apply(self, 'SA-01.14')
  only_if('/proc/cpuinfo exposes no CPU flags (non-x86 or restricted /proc)') { inspec.file('/proc/cpuinfo').content.to_s =~ /^flags/ }
  describe sdw_boot do
    its('cpu_nx') { should cmp true }
  end
  describe sdw_cmdline('noexec') do
    its('runtime') { should_not cmp 'off' }
    its('persistent') { should_not cmp 'off' }
  end
end
