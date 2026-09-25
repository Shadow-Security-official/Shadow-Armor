# frozen_string_literal: true

# Pillar 12 - Instaurez des politiques crypto / FIDO / MFA par OTP
# Crypto policy as the libraries negotiate it, SSH algorithms from sshd -T,
# post-quantum readiness, and second factors (OTP, FIDO2/U2F).

min_rsa = input('sdw_ssh_min_rsa_bits', value: sdw_catalog.default('sdw_ssh_min_rsa_bits')).to_i

crypto = sdw_crypto
sshd = sdw_sshd
sshc = sdw_ssh_crypto
mfa = sdw_mfa
sshd_missing = 'OpenSSH server (sshd) is not installed'

control 'SA-12.01' do
  sdw_catalog.apply(self, 'SA-12.01')
  only_if('no system-wide crypto policy framework (update-crypto-policies) on this distribution') { crypto.policy_tool? }
  describe crypto do
    its('policy') { should_not be_empty }
    its('policy') { should_not match(/\ALEGACY/) }
  end
end

control 'SA-12.02' do
  sdw_catalog.apply(self, 'SA-12.02')
  only_if('the openssl CLI is not installed') { command('openssl').exist? }
  describe SdwFindings.new("protocols below TLS 1.2 still usable with the system OpenSSL (#{crypto.openssl_version})", crypto.legacy_tls_usable) do
    its('items') { should be_empty }
  end
end

control 'SA-12.03' do
  sdw_catalog.apply(self, 'SA-12.03')
  only_if(sshd_missing) { sshd.installed? }
  describe sshc do
    its('weak_ciphers') { should be_empty }
  end
end

control 'SA-12.04' do
  sdw_catalog.apply(self, 'SA-12.04')
  only_if(sshd_missing) { sshd.installed? }
  describe sshc do
    its('weak_macs') { should be_empty }
  end
end

control 'SA-12.05' do
  sdw_catalog.apply(self, 'SA-12.05')
  only_if(sshd_missing) { sshd.installed? }
  describe sshc do
    its('weak_kex') { should be_empty }
  end
end

control 'SA-12.06' do
  sdw_catalog.apply(self, 'SA-12.06')
  only_if(sshd_missing) { sshd.installed? }
  describe SdwFindings.new("weak host keys loaded by sshd (DSA, RSA < #{min_rsa} bits)", sshc.weak_host_keys(min_rsa)) do
    its('items') { should be_empty }
  end
  describe sshc do
    its('weak_pubkey_algorithms') { should be_empty }
  end
end

control 'SA-12.07' do
  sdw_catalog.apply(self, 'SA-12.07')
  only_if(sshd_missing) { sshd.installed? }
  describe sshc do
    its('pq_kex_preferred') { should cmp true }
  end
end

control 'SA-12.08' do
  sdw_catalog.apply(self, 'SA-12.08')
  only_if(sshd_missing) { sshd.installed? }
  one_factor = mfa.ssh_mfa_enforced ? [] : ["AuthenticationMethods #{sshd.value('authenticationmethods') || 'any'}: one factor (a key or a password) is enough to log in"]
  describe SdwFindings.new('SSH logins that need a single factor (sshd -T AuthenticationMethods, FIDO2 verify-required keys)', one_factor) do
    its('items') { should be_empty }
  end
end

control 'SA-12.09' do
  sdw_catalog.apply(self, 'SA-12.09')
  only_if('sudo has no PAM configuration') { file('/etc/pam.d/sudo').exist? }
  describe SdwFindings.new('second-factor PAM modules in the sudo auth stack', mfa.sudo_second_factor) do
    its('items') { should_not be_empty }
  end
end

control 'SA-12.10' do
  sdw_catalog.apply(self, 'SA-12.10')
  only_if('no OTP seed or FIDO key map file on this host') { !mfa.secret_files.empty? }
  describe SdwFindings.new("OTP seed / FIDO key map files exposed beyond their owner (#{mfa.secret_files.size} found)", mfa.secret_file_problems) do
    its('items') { should be_empty }
  end
end

control 'SA-12.11' do
  sdw_catalog.apply(self, 'SA-12.11')
  describe SdwState.new('kernel FIPS mode (/proc/sys/crypto/fips_enabled; fips=1 on the next boot)',
                        runtime: crypto.fips_runtime, persistent: sdw_cmdline('fips').persistent == '1') do
    its('runtime') { should cmp true }
    its('persistent') { should cmp true }
  end
end
