# frozen_string_literal: true

# Effective PAM stack of a service: /etc/pam.d/<service> with every
# @include / include / substack expanded, in the order libpam runs it.
class ::SdwPam < Inspec.resource(1)
  name 'sdw_pam'
  desc 'Effective PAM stack of a service (includes and substacks expanded).'
  example "describe sdw_pam('sshd').stack('auth') do\n  its('modules') { should include 'pam_faillock.so' }\nend"

  include SdwHelpers

  attr_reader :service

  def initialize(service)
    @service = service
  end

  def exists?
    !read_file(path(@service)).nil?
  end

  # [{type:, control:, module:, args: [], file:}]
  def entries
    SdwMemo.fetch([:pam, @service]) { expand(@service, nil, 0) }
  end

  def stack(type)
    SdwPamStack.new(self, type, entries.select { |e| e[:type] == type })
  end

  def to_s
    "PAM service #{@service}"
  end

  private

  def path(svc)
    svc.start_with?('/') ? svc : "/etc/pam.d/#{svc}"
  end

  def expand(svc, only_type, depth)
    return [] if depth > 10

    content = read_file(path(svc))
    return [] unless content

    out = []
    content.each_line do |raw|
      line = raw.sub(/#.*$/, '').strip
      next if line.empty?

      if (m = line.match(/\A@include\s+(\S+)/))
        out.concat(expand(m[1], only_type, depth + 1))
        next
      end
      m = line.match(/\A-?(\w+)\s+(\[[^\]]*\]|\S+)\s*(.*)\z/)
      next unless m

      type = m[1].downcase
      control = m[2]
      rest = m[3].to_s.split(/\s+/)
      next if only_type && type != only_type

      if %w[include substack].include?(control)
        out.concat(expand(rest.first.to_s, type, depth + 1))
        next
      end
      mod = rest.shift.to_s
      out << { type: type, control: control, module: File.basename(mod), args: rest, file: path(svc) }
    end
    out
  end
end

class ::SdwPamStack
  attr_reader :type, :entries

  def initialize(pam, type, entries)
    @pam = pam
    @type = type
    @entries = entries
  end

  def modules
    @entries.map { |e| e[:module] }
  end

  def include?(mod)
    modules.include?(mod)
  end

  # Arguments of the first occurrence of a module, as {"key" => "value"|true}.
  def args(mod)
    e = @entries.find { |x| x[:module] == mod }
    return {} unless e

    e[:args].to_h { |a| k, v = a.split('=', 2); [k, v.nil? ? true : v] }
  end

  # Entries that short-circuit authentication straight to success.
  def permissive_shortcuts
    @entries.select do |e|
      e[:module] == 'pam_permit.so' &&
        (e[:control] == 'sufficient' || e[:control] =~ /success=done/)
    end.map { |e| "#{e[:file]}: #{e[:type]} #{e[:control]} #{e[:module]}" }
  end

  def to_s
    "PAM #{@pam.service} #{@type} stack"
  end
  alias inspect to_s
end
