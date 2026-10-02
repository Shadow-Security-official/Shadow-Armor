# frozen_string_literal: true

# Installed packages, read once from the package database (dpkg or rpm) and
# memoized: dozens of controls ask "is X installed?" and each question would
# otherwise be one remote round trip.
class ::SdwPackages < Inspec.resource(1)
  name 'sdw_packages'
  desc 'Installed package inventory (dpkg/rpm), queried once per scan.'
  example "describe sdw_packages.installed(%w[telnet rsh-client]) do\n  it { should be_empty }\nend"

  include SdwHelpers

  def manager
    SdwMemo.fetch(:pkg_manager) do
      if which('dpkg-query') then :dpkg
      elsif which('rpm') then :rpm
      elsif which('apk') then :apk
      end
    end
  end

  # name => version
  def all
    SdwMemo.fetch(:pkg_all) do
      h = {}
      case manager
      when :dpkg
        out = cmd_ok("dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\n' 2>/dev/null")
        out.to_s.each_line do |l|
          st, n, v = l.chomp.split("\t")
          h[n] = v if st.to_s.start_with?('ii') || st.to_s.start_with?('hi')
        end
      when :rpm
        out = cmd_ok("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null")
        out.to_s.each_line do |l|
          n, v = l.chomp.split("\t")
          h[n] = v if n
        end
      when :apk
        out = cmd_ok('apk info -v 2>/dev/null')
        out.to_s.each_line do |l|
          m = l.strip.match(/\A(.+)-([^-]+-r\d+)\z/)
          h[m[1]] = m[2] if m
        end
      end
      h
    end
  end

  def installed?(name)
    all.key?(name)
  end

  # Subset of names that are installed (evidence-friendly: the failing list).
  def installed(names)
    Array(names).select { |n| installed?(n) }
  end

  # Names matching a glob (e.g. 'linux-image-*').
  def matching(glob)
    all.keys.select { |n| File.fnmatch(glob, n) }
  end

  def to_s
    "installed packages (#{manager || 'no package manager'})"
  end
end
