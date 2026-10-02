# frozen_string_literal: true

# Pillar 14 - Protégez l'accès et la configuration de vos bases de données
# Databases.

db = sdw_databases(
  pg_user: input('sdw_postgres_os_user', value: sdw_catalog.default('sdw_postgres_os_user')),
  mysql_options: input('sdw_mysql_client_options', value: sdw_catalog.default('sdw_mysql_client_options'))
)

control 'SA-14.01' do
  sdw_catalog.apply(self, 'SA-14.01')
  only_if('no database server running') { db.any? }
  describe db do
    its('auth_gaps') { should be_empty }
    its('runtime_auth_gaps') { should be_empty }
  end
end

control 'SA-14.02' do
  sdw_catalog.apply(self, 'SA-14.02')
  only_if('PostgreSQL is not running') { db.running?('postgresql') }
  describe db do
    its('pg_weak_password_methods') { should be_empty }
  end
end

control 'SA-14.03' do
  sdw_catalog.apply(self, 'SA-14.03')
  only_if('no database server running') { db.any? }
  describe db do
    its('plaintext_network') { should be_empty }
  end
end

control 'SA-14.04' do
  sdw_catalog.apply(self, 'SA-14.04')
  only_if('PostgreSQL is not running') { db.running?('postgresql') }
  describe db do
    its('pg_connection_logging_off') { should be_empty }
  end
end

control 'SA-14.05' do
  sdw_catalog.apply(self, 'SA-14.05')
  only_if('MySQL/MariaDB is not running') { db.running?('mysql') }
  describe db do
    its('mysql_remote_admin_accounts') { should be_empty }
  end
end

control 'SA-14.06' do
  sdw_catalog.apply(self, 'SA-14.06')
  only_if('MySQL/MariaDB is not running') { db.running?('mysql') }
  describe db do
    its('runtime_local_infile') { should be_empty }
    its('persistent_local_infile') { should be_empty }
  end
end

control 'SA-14.07' do
  sdw_catalog.apply(self, 'SA-14.07')
  only_if('MySQL/MariaDB is not running') { db.running?('mysql') }
  describe db do
    its('runtime_open_file_priv') { should be_empty }
    its('persistent_open_file_priv') { should be_empty }
  end
end

control 'SA-14.08' do
  sdw_catalog.apply(self, 'SA-14.08')
  only_if('Redis/Valkey is not running') { db.running?('redis') }
  describe db do
    its('redis_dangerous_commands') { should be_empty }
  end
end

control 'SA-14.09' do
  sdw_catalog.apply(self, 'SA-14.09')
  only_if('Memcached is not running') { db.running?('memcached') }
  describe db do
    its('runtime_memcached_udp') { should be_empty }
  end
end

control 'SA-14.10' do
  sdw_catalog.apply(self, 'SA-14.10')
  only_if('MongoDB is not running') { db.running?('mongodb') }
  describe db do
    its('mongo_javascript') { should be_empty }
  end
end

control 'SA-14.11' do
  sdw_catalog.apply(self, 'SA-14.11')
  only_if('no database server running') { db.any? }
  describe db do
    its('runtime_root_servers') { should be_empty }
  end
end

control 'SA-14.12' do
  sdw_catalog.apply(self, 'SA-14.12')
  only_if('no database server running') { db.any? }
  describe db do
    its('open_data_dirs') { should be_empty }
  end
end
