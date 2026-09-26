# frozen_string_literal: true

# The machine under the kernel: CPU flaws and their mitigations, SMT, the
# IOMMU that stops DMA from peripherals, Thunderbolt and FireWire, the TPM,
# the BMC (IPMI) and pending firmware updates (fwupd). Most of it only means
# something on physical hardware: `virtual` names the hypervisor otherwise.
class ::SdwHardware < Inspec.resource(1)
  name 'sdw_hardware'
  desc 'CPU mitigations, SMT, IOMMU, DMA ports, TPM, BMC and firmware updates.'
  example "describe sdw_hardware do\n  its('vulnerable_flaws') { should be_empty }\nend"

  include SdwHelpers

  VIRT_VENDORS = /KVM|QEMU|VMware|VirtualBox|innotek|Xen|Bochs|Parallels|Microsoft Corporation Virtual|Amazon EC2|Google Compute Engine|OpenStack|BHYVE|Hetzner vServer|DigitalOcean/i.freeze

  # Hypervisor name inside a virtual machine, nil on bare metal.
  def virtual
    SdwMemo.fetch(:hw_virtual) do
      v = which('systemd-detect-virt') ? cmd_ok('systemd-detect-virt --vm 2>/dev/null').to_s.strip : ''
      v = '' if v == 'none'
      if v.empty?
        dmi = %w[sys_vendor product_name board_vendor].map { |f| read_file("/sys/class/dmi/id/#{f}").to_s.strip }.join(' ')
        v = dmi[VIRT_VENDORS].to_s
      end
      v = 'hypervisor' if v.empty? && read_file('/proc/cpuinfo').to_s =~ /^flags\s*:.*\bhypervisor\b/
      v.empty? ? nil : v
    end
  end

  def virtual?
    !virtual.nil?
  end

  def x86?
    SdwMemo.fetch(:hw_x86) { cmd_ok('uname -m').to_s.strip =~ /\A(x86_64|i[3-6]86)\z/ ? true : false }
  end

  # 'intel', 'amd' or nil.
  def cpu_vendor
    SdwMemo.fetch(:hw_cpu_vendor) do
      case read_file('/proc/cpuinfo').to_s[/^vendor_id\s*:\s*(\S+)/, 1]
      when 'GenuineIntel' then 'intel'
      when 'AuthenticAMD', 'HygonGenuine' then 'amd'
      end
    end
  end

  # ── CPU flaws ──────────────────────────────────────────────────────────

  # { flaw => kernel status } from /sys/devices/system/cpu/vulnerabilities.
  def cpu_vulns
    SdwMemo.fetch(:hw_cpu_vulns) do
      out = cmd_ok('for f in /sys/devices/system/cpu/vulnerabilities/*; do [ -r "$f" ] && printf "%s\t%s\n" "${f##*/}" "$(cat "$f")"; done 2>/dev/null')
      out.to_s.lines.to_h { |l| l.chomp.split("\t", 2) }.reject { |k, _| k.to_s.empty? }
    end
  end

  def cpu_vulns_readable?
    !cpu_vulns.empty?
  end

  # Flaws the kernel reports as not mitigated on this CPU and microcode (a
  # fact of the hardware, the microcode and the kernel: a reboot alone does
  # not change it).
  def vulnerable_flaws
    SdwParse.cpu_vulnerable(cpu_vulns)
  end

  def runtime_mitigations_off
    SdwParse.mitigation_off_params(read_file('/proc/cmdline')).map { |p| "#{p} on the running kernel" }
  end

  def persistent_mitigations_off
    SdwParse.mitigation_off_params(boot_line).map { |p| "#{p} in the boot configuration" }
  end

  # ── SMT ────────────────────────────────────────────────────────────────

  # 'on', 'off', 'forceoff', 'notsupported', 'notimplemented' or nil.
  def smt_control
    read_file('/sys/devices/system/cpu/smt/control')&.strip
  end

  def smt_capable?
    %w[on off forceoff].include?(smt_control)
  end

  # Flaws whose mitigation stays incomplete while sibling threads run.
  def runtime_smt_exposed
    return [] unless read_file('/sys/devices/system/cpu/smt/active')&.strip == '1'

    SdwParse.cpu_smt_exposed(cpu_vulns)
  end

  # The same flaws (or those mitigated today by SMT off) with nothing on the
  # boot line to keep SMT off after a reboot.
  def persistent_smt_exposed
    return [] unless smt_capable?

    needed = cpu_vulns.select { |_, s| s.to_s =~ /SMT (vulnerable|Host state unknown|disabled)/i }.keys.sort
    return [] if needed.empty? || SdwParse.nosmt_at_boot?(boot_line)

    ["#{needed.join(', ')} need SMT off, and neither nosmt nor mitigations=auto,nosmt is on the boot line"]
  end

  # ── IOMMU and DMA ports ────────────────────────────────────────────────

  def runtime_iommu_active
    !list_dir('/sys/class/iommu').empty? && SdwParse.iommu_off_params(read_file('/proc/cmdline')).empty?
  end

  # No boot parameter turns it off, and it is either on now or explicitly
  # requested for the next boot.
  def persistent_iommu_enabled
    line = boot_line
    return false unless SdwParse.iommu_off_params(line).empty?

    runtime_iommu_active || line.split.any? { |t| t =~ /\A(intel_iommu=on|amd_iommu=on|iommu=force)\z/ }
  end

  def iommu_off_on_boot_line
    SdwParse.iommu_off_params(boot_line)
  end

  def thunderbolt_domains
    list_dir('/sys/bus/thunderbolt/devices', 'domain*')
  end

  # Domains that let any device do DMA ("none") without the kernel's
  # pre-boot DMA protection.
  def thunderbolt_insecure
    thunderbolt_domains.filter_map do |d|
      sec = read_file("#{d}/security").to_s.strip
      prot = read_file("#{d}/iommu_dma_protection").to_s.strip
      "#{File.basename(d)}: security level '#{sec}'" if sec == 'none' && prot != '1'
    end
  end

  # ── TPM ────────────────────────────────────────────────────────────────

  # Major version of the first TPM, nil when there is none.
  def tpm_version
    SdwMemo.fetch(:hw_tpm) do
      dev = list_dir('/sys/class/tpm', 'tpm*').first
      if dev.nil? then nil
      elsif (v = read_file("#{dev}/tpm_version_major")&.strip) && !v.empty? then v.to_i
      elsif inspec.file("#{dev}/device/caps").exist? then 1
      else 2
      end
    end
  end

  # ── BMC (IPMI) ─────────────────────────────────────────────────────────

  def bmc?
    %w[/dev/ipmi0 /dev/ipmi/0 /dev/ipmidev/0].any? { |d| inspec.file(d).exist? } || !list_dir('/sys/class/ipmi').empty?
  end

  # LAN channels of the BMC that accept cipher suite 0 or NONE authentication.
  def ipmi_weak_lan
    return [] unless bmc?
    return ['a BMC is present but ipmitool is not installed: its LAN settings cannot be read'] unless which('ipmitool')

    out = []
    seen = false
    (1..11).each do |ch|
      text = cmd_ok("timeout 10 ipmitool lan print #{ch} 2>/dev/null")
      next if text.to_s.strip.empty?

      seen = true
      out << "LAN channel #{ch}: cipher suite 0 (no authentication) enabled" if SdwParse.ipmi_cipher0_enabled?(text)
      none = SdwParse.ipmi_none_auth(text)
      out << "LAN channel #{ch}: authentication type NONE enabled for #{none.join(', ')}" unless none.empty?
    end
    seen ? out : ['a BMC is present but `ipmitool lan print` answered on no channel']
  end

  # ── Firmware updates ───────────────────────────────────────────────────

  def fwupd?
    !which('fwupdmgr').nil?
  end

  # [:ok|:pending|:unknown, detail]
  def fwupd
    SdwMemo.fetch(:hw_fwupd) do
      r = sh('timeout 60 fwupdmgr get-updates --json --no-unreported-check --no-metadata-check')
      SdwParse.fwupd_state(r.exit_status, r.stdout, r.stderr)
    end
  end

  def firmware_updates
    state, detail = fwupd
    case state
    when :ok then []
    when :pending then Array(detail)
    else ["fwupd could not tell: #{detail}"]
    end
  end

  # ── USB device policy ──────────────────────────────────────────────────

  def runtime_usbguard_active
    inspec.sdw_unit('usbguard.service').runtime_active
  end

  def persistent_usbguard_enabled
    inspec.sdw_unit('usbguard.service').persistent_enabled
  end

  # Problems of the policy files: an empty rule set, or unknown devices
  # allowed by default.
  def usbguard_policy_gaps
    conf = read_file('/etc/usbguard/usbguard-daemon.conf').to_s
    target = conf[/^\s*ImplicitPolicyTarget\s*=\s*(\S+)/, 1] || 'block'
    rules_file = conf[/^\s*RuleFile\s*=\s*(\S+)/, 1] || '/etc/usbguard/rules.conf'
    rules = meaningful_lines(read_file(rules_file)) + list_dir('/etc/usbguard/rules.d', '*.conf').flat_map { |f| meaningful_lines(read_file(f)) }
    out = []
    out << "ImplicitPolicyTarget=#{target} (unknown devices are not blocked)" if target != 'block' && target != 'reject'
    out << "no rule in #{rules_file} (generate one with `usbguard generate-policy`)" if rules.empty?
    out
  end

  def to_s
    virtual? ? "hardware (virtual machine: #{virtual})" : 'hardware'
  end

  private

  # Kernel command line of the next boot; the running one when no boot
  # loader configuration could be read.
  def boot_line
    c = inspec.sdw_cmdline('mitigations')
    c.persistent_origin == 'none' ? read_file('/proc/cmdline').to_s : c.boot_line.to_s
  end
end
