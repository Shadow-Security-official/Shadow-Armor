# frozen_string_literal: true

require 'time'

# TLS services listening on the target, probed from the target itself with
# the openssl CLI: which ports complete a TLS handshake, whether they still
# accept TLS 1.0 or 1.1, the certificate they present, and the HSTS header of
# the HTTPS ones. Everything here is what a client sees now (runtime).
class ::SdwTlsEndpoints < Inspec.resource(1)
  name 'sdw_tls_endpoints'
  desc 'TLS endpoints listening now, probed with openssl.'
  example "describe sdw_tls_endpoints do\n  its('runtime_legacy_protocols') { should be_empty }\nend"

  include SdwHelpers

  def initialize(opts = {})
    @min_days = opts.fetch(:min_days, 30).to_i
    @min_rsa = opts.fetch(:min_rsa, 2048).to_i
    @min_hsts = opts.fetch(:min_hsts, 15_768_000).to_i
  end

  def openssl?
    !which('openssl').nil?
  end

  # ["127.0.0.1:443", ...]: TCP listeners that complete a TLS handshake.
  def endpoints
    SdwMemo.fetch(:tls_endpoints) do
      targets.select { |t| handshake?(t) }
    end
  end

  def any?
    !endpoints.empty?
  end

  def runtime_legacy_protocols
    out = []
    endpoints.each do |t|
      { 'TLSv1' => '-tls1', 'TLSv1.1' => '-tls1_1' }.each do |name, flag|
        next unless legacy_flag?(flag)

        out << "#{t} accepts #{name}" if handshake?(t, "#{flag} -cipher DEFAULT@SECLEVEL=0")
      end
    end
    out
  end

  def runtime_expiring_certificates
    now = Time.now
    endpoints.filter_map do |t|
      f = cert(t)
      next "#{t}: certificate unreadable" unless f[:not_after]

      left = ((Time.parse(f[:not_after]) - now) / 86_400).floor
      if left.negative?
        "#{t}: certificate expired #{-left} day(s) ago (#{f[:not_after]})"
      elsif left < @min_days
        "#{t}: certificate expires in #{left} day(s) (#{f[:not_after]})"
      end
    rescue ArgumentError
      "#{t}: certificate end date unreadable (#{f[:not_after]})"
    end
  end

  def runtime_weak_keys
    endpoints.filter_map do |t|
      f = cert(t)
      "#{t}: #{f[:algorithm]} #{f[:bits]}-bit key" if SdwParse.weak_key?(f, @min_rsa)
    end
  end

  # HTTPS endpoints (the ones answering HTTP) without a long enough HSTS.
  def runtime_missing_hsts
    endpoints.filter_map do |t|
      raw = cmd_ok("printf 'HEAD / HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | " \
                   "timeout 6 openssl s_client -quiet -connect #{t} -servername localhost 2>/dev/null")
      next unless raw.to_s.start_with?('HTTP/')

      h = SdwParse.http_headers(raw)
      v = h['strict-transport-security']
      next if SdwParse.hsts_ok?(v, @min_hsts)

      "#{t}: #{v ? "Strict-Transport-Security \"#{v}\" (max-age below #{@min_hsts})" : 'no Strict-Transport-Security header'}"
    end
  end

  def to_s
    endpoints.empty? ? 'TLS endpoints (none found)' : "TLS endpoints (#{endpoints.join(', ')})"
  end

  private

  # One address per listening TCP port: the loopback when the socket is bound
  # to every address, else the bound address.
  def targets
    inspec.sdw_listen.sockets.select { |s| s[:proto].to_s.start_with?('tcp') }.map do |s|
      a = s[:addr].to_s
      host = if ['*', '0.0.0.0', '::', ''].include?(a) then '127.0.0.1'
             elsif a.include?(':') then "[#{a}]"
             else a
             end
      "#{host}:#{s[:port]}"
    end.uniq
  end

  def handshake?(target, extra = '')
    r = sh("echo | timeout 5 openssl s_client -connect #{target} -servername localhost #{extra} 2>&1")
    out = r.stdout.to_s
    r.exit_status.zero? && out.include?('Cipher is ') && !out.include?('Cipher is (NONE)')
  end

  def legacy_flag?(flag)
    SdwMemo.fetch([:openssl_flag, flag]) { sh("openssl s_client -help 2>&1").stdout.to_s.include?(flag) }
  end

  def cert(target)
    SdwMemo.fetch([:tls_cert, target]) do
      SdwParse.x509_facts(cmd_ok("echo | timeout 5 openssl s_client -connect #{target} -servername localhost 2>/dev/null | " \
                                 'openssl x509 -noout -enddate -text 2>/dev/null'))
    end
  end
end
