# frozen_string_literal: true

# Pillar 13 - Sécurisez vos services web et vos certificats TLS
# Web services & TLS.

web = sdw_web
tls = sdw_tls_endpoints(
  min_days: input('sdw_tls_min_days', value: sdw_catalog.default('sdw_tls_min_days')),
  min_rsa: input('sdw_tls_min_rsa_bits', value: sdw_catalog.default('sdw_tls_min_rsa_bits')),
  min_hsts: input('sdw_hsts_min_age', value: sdw_catalog.default('sdw_hsts_min_age'))
)

# TLS endpoint probes need openssl on the target and something to probe.
tls_applicable = lambda do
  only_if('openssl is not installed on the target: TLS endpoints cannot be probed') { tls.openssl? }
  only_if('no listening port completes a TLS handshake') { tls.any? }
end

control 'SA-13.01' do
  sdw_catalog.apply(self, 'SA-13.01')
  only_if('no nginx, Apache or lighttpd installed') { %w[nginx apache lighttpd].any? { |s| web.installed?(s) } }
  describe web do
    its('version_disclosure') { should be_empty }
  end
end

control 'SA-13.02' do
  sdw_catalog.apply(self, 'SA-13.02')
  only_if('no nginx, Apache or lighttpd installed') { %w[nginx apache lighttpd].any? { |s| web.installed?(s) } }
  describe web do
    its('directory_listing') { should be_empty }
  end
end

control 'SA-13.03' do
  sdw_catalog.apply(self, 'SA-13.03')
  only_if('no nginx, Apache or HAProxy installed') { %w[nginx apache haproxy].any? { |s| web.installed?(s) } }
  describe web do
    its('legacy_tls_config') { should be_empty }
  end
end

control 'SA-13.04' do
  sdw_catalog.apply(self, 'SA-13.04')
  only_if('no web server installed') { web.any? }
  describe web do
    its('config_root_workers') { should be_empty }
    its('runtime_root_workers') { should be_empty }
  end
end

control 'SA-13.05' do
  sdw_catalog.apply(self, 'SA-13.05')
  only_if('Apache httpd is not installed') { web.installed?('apache') }
  describe web do
    its('trace_enabled') { should be_empty }
  end
end

control 'SA-13.06' do
  sdw_catalog.apply(self, 'SA-13.06')
  only_if('HAProxy is not installed') { web.installed?('haproxy') }
  describe web do
    its('open_stats') { should be_empty }
  end
end

control 'SA-13.07' do
  sdw_catalog.apply(self, 'SA-13.07')
  only_if('Caddy is not installed') { web.installed?('caddy') }
  describe web do
    its('admin_exposed') { should be_empty }
  end
end

control 'SA-13.08' do
  sdw_catalog.apply(self, 'SA-13.08')
  only_if('no Tomcat instance found') { web.installed?('tomcat') }
  describe web do
    its('shutdown_port_open') { should be_empty }
  end
end

control 'SA-13.09' do
  sdw_catalog.apply(self, 'SA-13.09')
  only_if('no Tomcat instance found') { web.installed?('tomcat') }
  describe web do
    its('manager_apps') { should be_empty }
  end
end

control 'SA-13.10' do
  sdw_catalog.apply(self, 'SA-13.10')
  instance_exec(&tls_applicable)
  describe tls do
    its('runtime_legacy_protocols') { should be_empty }
  end
end

control 'SA-13.11' do
  sdw_catalog.apply(self, 'SA-13.11')
  instance_exec(&tls_applicable)
  describe tls do
    its('runtime_expiring_certificates') { should be_empty }
  end
end

control 'SA-13.12' do
  sdw_catalog.apply(self, 'SA-13.12')
  instance_exec(&tls_applicable)
  describe tls do
    its('runtime_weak_keys') { should be_empty }
  end
end

control 'SA-13.13' do
  sdw_catalog.apply(self, 'SA-13.13')
  instance_exec(&tls_applicable)
  describe tls do
    its('runtime_missing_hsts') { should be_empty }
  end
end
