# frozen_string_literal: true

# System cryptography as the libraries will actually negotiate it.
class ::SdwCrypto < Inspec.resource(1)
  name 'sdw_crypto'
  desc 'System-wide crypto policy, OpenSSL effective protocol floor, FIPS mode, SSH host keys.'
  example "describe sdw_crypto do\n  its('policy') { should_not match /LEGACY/ }\nend"

  include SdwHelpers

  WEAK_CIPHERS = /(cbc|3des|arcfour|rijndael|blowfish|cast128)/i
  WEAK_MACS = /\A(hmac-md5|hmac-md5-96|hmac-sha1|hmac-sha1-96|umac-64@openssh\.com|hmac-ripemd160|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-etm@openssh\.com)\z/i
  WEAK_KEX = /(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|gss-.*sha1|ecdh-sha2-nistp256-weak)/i
  PQ_KEX = /\A(mlkem768x25519-sha256|sntrup761x25519-sha512(@openssh\.com)?)\z/

  def policy_tool?
    !which('update-crypto-policies').nil?
  end

  def policy
    SdwMemo.fetch(:crypto_policy) { cmd_ok('update-crypto-policies --show 2>/dev/null').to_s.strip }
  end

  def fips_runtime
    read_file('/proc/sys/crypto/fips_enabled').to_s.strip == '1'
  end

  def openssl_version
    SdwMemo.fetch(:openssl_version) { cmd_ok('openssl version 2>/dev/null').to_s.strip }
  end

  # Can the system OpenSSL (with its default config) still negotiate a protocol
  # older than TLS 1.2? Probed with the library itself: `openssl ciphers -s`
  # lists what the security level and protocol floor really allow.
  def legacy_tls_usable
    SdwMemo.fetch(:legacy_tls) do
      raise ::Inspec::Exceptions::ResourceSkipped, 'openssl CLI not installed' unless which('openssl')

      usable = []
      { 'TLSv1.0' => '-tls1', 'TLSv1.1' => '-tls1_1' }.each do |name, flag|
        r = sh("openssl ciphers -s #{flag} 2>/dev/null")
        usable << name if r.exit_status.zero? && !r.stdout.strip.empty? && openssl_allows?(name)
      end
      usable
    end
  end

  def to_s
    'system cryptography'
  end

  private

  # `openssl ciphers -s -tls1_1` still prints suites when only MinProtocol
  # forbids TLS 1.1, so check the configured floor too (system_default section).
  def openssl_allows?(proto)
    rank = { 'TLSv1' => 0, 'TLSv1.0' => 0, 'TLSv1.1' => 1, 'TLSv1.2' => 2, 'TLSv1.3' => 3 }
    floor = SdwMemo.fetch(:openssl_floor) do
      dir = cmd_ok('openssl version -d 2>/dev/null').to_s[/"(.*)"/, 1]
      conf = ENV.fetch('OPENSSL_CONF', nil) || (dir ? "#{dir}/openssl.cnf" : '/etc/ssl/openssl.cnf')
      text = [conf, '/etc/crypto-policies/back-ends/opensslcnf.config'].map { |f| read_file(f) }.compact.join("\n")
      mins = text.scan(/^\s*MinProtocol\s*=\s*(\S+)/).flatten
      seclevel = text.scan(/@SECLEVEL=(\d)/).flatten.map(&:to_i)
      { min: mins.map { |m| rank[m] || 0 }.max, seclevel: seclevel.min }
    end
    # OpenSSL >= 3.0 refuses TLS < 1.2 at security level >= 1 (the default).
    v3 = openssl_version =~ /OpenSSL (\d+)\./ && Regexp.last_match(1).to_i >= 3
    return false if v3 && (floor[:seclevel].nil? || floor[:seclevel] >= 1)
    return false if floor[:min] && floor[:min] > rank[proto]

    true
  end
end

# SSH algorithm hygiene on top of the effective sshd configuration.
class ::SdwSshCrypto < Inspec.resource(1)
  name 'sdw_ssh_crypto'
  desc 'Weak or strong algorithms in the effective sshd configuration and host keys.'
  example "describe sdw_ssh_crypto do\n  its('weak_ciphers') { should be_empty }\nend"

  include SdwHelpers

  def sshd
    @sshd ||= inspec.sdw_sshd
  end

  def list(keyword)
    sshd.values(keyword).flat_map { |v| v.split(',') }.map(&:strip).reject(&:empty?)
  end

  def weak_ciphers
    list('ciphers').grep(SdwCrypto::WEAK_CIPHERS)
  end

  def weak_macs
    list('macs').grep(SdwCrypto::WEAK_MACS)
  end

  def weak_kex
    list('kexalgorithms').grep(SdwCrypto::WEAK_KEX)
  end

  def pq_kex
    list('kexalgorithms').grep(SdwCrypto::PQ_KEX)
  end

  def pq_kex_preferred
    first = list('kexalgorithms').first.to_s
    first.match?(SdwCrypto::PQ_KEX)
  end

  def weak_pubkey_algorithms
    (list('pubkeyacceptedalgorithms') + list('pubkeyacceptedkeytypes') + list('hostkeyalgorithms')).uniq.select do |a|
      a =~ /\A(ssh-dss|ssh-rsa|ssh-rsa-cert-v01@openssh\.com|ssh-dss-cert-v01@openssh\.com)\z/
    end
  end

  # Host keys sshd loads that are DSA, or RSA shorter than min_rsa bits.
  def weak_host_keys(min_rsa)
    sshd.values('hostkey').filter_map do |path|
      out = cmd_ok("ssh-keygen -l -f #{Shellwords.escape(path)} 2>/dev/null").to_s.strip
      next "#{path}: unreadable" if out.empty? && inspec.file(path).exist?
      next nil if out.empty?

      bits = out.split.first.to_i
      type = out[/\(([^)]+)\)\s*\z/, 1].to_s
      if type =~ /DSA/ && type !~ /ECDSA/
        "#{path}: DSA #{bits}"
      elsif type =~ /RSA/ && bits < min_rsa
        "#{path}: RSA #{bits} bits"
      end
    end
  end

  def to_s
    'sshd -T algorithms'
  end
end

# Multi-factor authentication posture.
class ::SdwMfa < Inspec.resource(1)
  name 'sdw_mfa'
  desc 'Second factors wired into SSH and privilege escalation (OTP, FIDO/U2F), and protection of their secrets.'
  example "describe sdw_mfa do\n  its('ssh_mfa_enforced') { should cmp true }\nend"

  include SdwHelpers

  OTP = %w[pam_google_authenticator.so pam_oath.so pam_totp.so].freeze
  FIDO = %w[pam_u2f.so pam_yubico.so].freeze
  PUSH = %w[pam_duo.so pam_radius_auth.so pam_privacyidea.so pam_linotp.so].freeze
  SECOND_FACTOR = (OTP + FIDO + PUSH).freeze

  def second_factor_modules(service)
    pam = inspec.sdw_pam(service)
    return [] unless pam.exists?

    pam.stack('auth').modules & SECOND_FACTOR
  end

  # Every AuthenticationMethods list demands two distinct factors, or public
  # keys are restricted to FIDO2 hardware keys that verify the user (PIN).
  def ssh_mfa_enforced
    ssh_mfa_evidence != 'none'
  end

  def ssh_mfa_evidence
    SdwMemo.fetch(:ssh_mfa) do
      sshd = inspec.sdw_sshd
      pam2f = second_factor_modules('sshd')
      pam = inspec.sdw_pam('sshd')
      pam_pw = pam.exists? && !(pam.stack('auth').modules & %w[pam_unix.so pam_sss.so pam_ldap.so]).empty?
      kbd = if pam2f.empty? then ['password']
            elsif pam_pw then %w[password second-factor]
            else ['second-factor']
            end
      factors = lambda do |method|
        case method.split(':').first
        when 'publickey' then ['key']
        when 'password' then ['password']
        when 'keyboard-interactive' then kbd
        when 'gssapi-with-mic' then ['kerberos']
        else []
        end
      end
      methods = sshd.value('authenticationmethods').to_s.strip
      lists = methods.split(/\s+/)
      algos = sshd.value('pubkeyacceptedalgorithms').to_s.split(',')
      if !methods.empty? && methods != 'any' && lists.all? { |l| l.split(',').flat_map(&factors).uniq.size >= 2 }
        "AuthenticationMethods #{methods}#{pam2f.empty? ? '' : " (PAM: #{pam2f.join(', ')})"}"
      elsif (methods.empty? || methods == 'any') && sshd.value('pubkeyauthentication') == 'no' &&
            sshd.value('passwordauthentication') == 'no' && sshd.value('kbdinteractiveauthentication') == 'yes' && kbd.size >= 2
        "keyboard-interactive only, PAM requires password + #{pam2f.join(', ')}"
      elsif !algos.empty? && algos.all? { |a| a.start_with?('sk-') } && sshd.value('pubkeyauthoptions').to_s.include?('verify-required') &&
            sshd.value('passwordauthentication') == 'no' && sshd.value('kbdinteractiveauthentication') != 'yes'
        'FIDO2 hardware keys only (sk-*) with PubkeyAuthOptions verify-required'
      else
        'none'
      end
    end
  end

  def sudo_second_factor
    second_factor_modules('sudo')
  end

  # OTP seed / U2F key map files present on the host: [{path:, owner:}]
  def secret_files
    SdwMemo.fetch(:mfa_secret_files) do
      files = []
      oath = %w[sshd sudo login common-auth system-auth].flat_map do |svc|
        pam = inspec.sdw_pam(svc)
        pam.exists? ? pam.entries.select { |e| e[:module] == 'pam_oath.so' }.map { |e| e[:args].find { |a| a.start_with?('usersfile=') }.to_s.split('=', 2).last } : []
      end.compact.uniq
      oath << '/etc/users.oath' if oath.empty?
      oath.each { |f| files << { path: f, owner: 'root' } if inspec.file(f).exist? }
      inspec.sdw_accounts.interactive_users.each do |u|
        %w[.google_authenticator .config/Yubico/u2f_keys].each do |rel|
          p = File.join(u[:home].to_s, rel)
          files << { path: p, owner: u[:name] } if inspec.file(p).exist?
        end
      end
      files
    end
  end

  # Those files readable/writable beyond their owner, or owned by someone else.
  def secret_file_problems
    secret_files.flat_map do |f|
      st = inspec.file(f[:path])
      probs = []
      probs << "#{f[:path]}: mode #{format('%04o', st.mode)}" if (st.mode & 0o077) != 0
      probs << "#{f[:path]}: owner #{st.owner} (expected #{f[:owner]})" if st.owner != f[:owner]
      probs
    end
  end

  def to_s
    'multi-factor authentication'
  end
end

# systemd sandboxing of the services that are reachable from the network.
class ::SdwSandbox < Inspec.resource(1)
  name 'sdw_sandbox'
  desc 'systemd-analyze security exposure of network-facing services.'
  example "describe sdw_sandbox do\n  its('unsafe_exposed_services') { should be_empty }\nend"

  include SdwHelpers

  def exposures
    SdwMemo.fetch(:sandbox) do
      out = which('systemd-analyze') ? cmd_ok('systemd-analyze security --no-pager 2>/dev/null').to_s : ''
      out.lines.filter_map do |l|
        f = l.split
        [f[0], f[1].to_f] if f.size >= 3 && f[1] =~ /\A\d+(\.\d+)?\z/
      end.to_h
    end
  end

  def exposed_units
    SdwMemo.fetch(:exposed_units) do
      pids = cmd_ok('ss -H -tulnp 2>/dev/null').to_s.scan(/pid=(\d+)/).flatten.uniq
      listen = inspec.sdw_listen
      exposed_pids = listen.exposed.map { |s| s[:process] }.compact
      next [] if exposed_pids.empty?

      pids.filter_map { |pid| cmd_ok("ps -o unit= -p #{pid} 2>/dev/null").to_s.strip }.reject(&:empty?).uniq
    end
  end

  def unsafe_exposed_services(max, exempt)
    exposed_units.reject { |u| exempt.include?(u) }.filter_map do |u|
      score = exposures[u]
      "#{u} exposure #{score}" if score && score > max
    end
  end

  def to_s
    'service sandboxing (systemd-analyze security)'
  end
end
