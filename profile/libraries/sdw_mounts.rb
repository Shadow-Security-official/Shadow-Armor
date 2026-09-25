# frozen_string_literal: true

# A mount point, audited twice:
#   runtime_*    -> what the kernel has mounted now (findmnt / /proc/self/mounts)
#   persistent_* -> what will be mounted at boot (/etc/fstab, or a systemd
#                   .mount unit such as tmp.mount, with its drop-ins)
class ::SdwMount < Inspec.resource(1)
  name 'sdw_mount'
  desc 'Mount point options now (kernel) and at boot (fstab / systemd mount unit).'
  example "describe sdw_mount('/tmp') do\n  its('runtime_options') { should include 'nosuid' }\n  its('persistent_options') { should include 'nosuid' }\nend"

  include SdwHelpers

  attr_reader :path

  def initialize(path)
    @path = path
  end

  def runtime_mounted
    !runtime_entry.nil?
  end

  def runtime_options
    runtime_entry ? runtime_entry[:options] : []
  end

  def runtime_fstype
    runtime_entry && runtime_entry[:fstype]
  end

  def runtime_source
    runtime_entry && runtime_entry[:source]
  end

  def persistent_mounted
    !persistent_entry.nil?
  end

  def persistent_options
    persistent_entry ? persistent_entry[:options] : []
  end

  def persistent_origin
    persistent_entry ? persistent_entry[:origin] : 'none'
  end

  def to_s
    "mount #{@path}"
  end

  def self.table(res)
    SdwMemo.fetch(:mounts) do
      rows = {}
      text = res.read_file('/proc/self/mounts') || ''
      text.each_line do |l|
        src, target, fstype, opts = l.split
        next unless target

        target = target.gsub('\\040', ' ')
        rows[target] = { source: src, fstype: fstype, options: opts.to_s.split(',') }
      end
      rows
    end
  end

  private

  def runtime_entry
    self.class.table(self)[@path]
  end

  def persistent_entry
    SdwMemo.fetch([:mount_persist, @path]) do
      entry = nil
      (read_file('/etc/fstab') || '').each_line do |l|
        next if l.strip.start_with?('#')

        src, target, fstype, opts = l.split
        next unless target == @path

        entry = { source: src, fstype: fstype, options: opts.to_s.split(','), origin: '/etc/fstab' }
      end
      entry ||= mount_unit
      entry
    end
  end

  # systemd .mount unit (e.g. tmp.mount) that is enabled or pulled in at boot.
  def mount_unit
    unit = @path == '/' ? '-.mount' : "#{@path.delete_prefix('/').gsub('/', '-')}.mount"
    return nil unless which('systemctl')

    st = sh("systemctl is-enabled #{Shellwords.escape(unit)} 2>/dev/null").stdout.to_s.strip
    return nil unless %w[enabled static enabled-runtime generated].include?(st)

    out = cmd_ok("systemctl cat #{Shellwords.escape(unit)} 2>/dev/null")
    return nil unless out

    opts = []
    what = nil
    type = nil
    out.each_line do |l|
      k, v = l.strip.split('=', 2)
      case k
      when 'Options' then opts = v.to_s.split(',')
      when 'What' then what = v
      when 'Type' then type = v
      end
    end
    { source: what, fstype: type, options: opts, origin: "systemd #{unit}" }
  end
end

# Block device tree (lsblk), to prove data really sits on dm-crypt.
class ::SdwBlock < Inspec.resource(1)
  name 'sdw_block'
  desc 'Block devices: is a mount point or swap device backed by an encrypted (dm-crypt/LUKS) layer.'
  example "describe sdw_block.encryption_of('/') do\n  its('runtime') { should cmp 'crypt' }\nend"

  include SdwHelpers

  def devices
    SdwMemo.fetch(:lsblk) do
      out = which('lsblk') ? cmd_ok('lsblk -J -p -o NAME,KNAME,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null') : nil
      tree = begin
        out ? JSON.parse(out)['blockdevices'] : []
      rescue JSON::ParserError
        []
      end
      flat = {}
      walk = lambda do |nodes, ancestors|
        Array(nodes).each do |n|
          chain = ancestors + [n]
          entry = { type: n['type'], fstype: n['fstype'], mountpoint: n['mountpoint'], chain: chain.map { |c| { name: c['name'], type: c['type'], fstype: c['fstype'] } } }
          flat[n['name']] = entry
          flat[n['kname']] ||= entry if n['kname']
          walk.call(n['children'], chain)
        end
      end
      walk.call(tree, [])
      flat
    end
  end

  # How the device behind a mount point (or a device path) is protected:
  # 'crypt' (dm-crypt/LUKS in the chain), 'zram' (RAM-only), or 'plain'.
  def protection_of_device(dev)
    real = resolve(dev)
    d = devices[dev] || devices[real]
    return 'unknown' unless d

    types = d[:chain].map { |c| c[:type] }
    return 'crypt' if types.include?('crypt') || d[:chain].any? { |c| c[:fstype] == 'crypto_LUKS' }
    return 'zram' if real.to_s.include?('/dev/zram')

    'plain'
  end

  def encryption_of(mountpoint)
    SdwEncryption.new(self, mountpoint)
  end

  # Swap specs /etc/fstab activates at boot (noauto entries excluded).
  def fstab_swaps
    SdwMemo.fetch(:fstab_swaps) do
      meaningful_lines(read_file('/etc/fstab')).map(&:split).select do |f|
        f.size >= 3 && f[2] == 'swap' && !f[3].to_s.split(',').include?('noauto')
      end.map(&:first)
    end
  end

  def crypttab
    SdwMemo.fetch(:crypttab) do
      meaningful_lines(read_file('/etc/crypttab')).map { |l| n, dev, key, opts = l.split; { name: n, device: dev, key: key, options: opts.to_s.split(',') } }
    end
  end

  def resolve(dev)
    return dev unless dev.to_s.start_with?('/dev/')

    SdwMemo.fetch([:realpath, dev]) do
      out = cmd_ok("readlink -f #{Shellwords.escape(dev)} 2>/dev/null").to_s.strip
      out.empty? ? dev : out
    end
  end

  def to_s
    'block devices'
  end
end

class ::SdwEncryption
  def initialize(block, mountpoint)
    @block = block
    @mountpoint = mountpoint
  end

  def mounted?
    !SdwMount.table(@block)[@mountpoint].nil?
  end

  # Protection of the storage mounted there: a property of the block stack
  # (dm-crypt/LUKS on disk), durable by nature, read from the live mount.
  def protection
    m = SdwMount.table(@block)[@mountpoint]
    return 'not-mounted' unless m

    src = m[:source]
    return 'tmpfs' if %w[tmpfs ramfs].include?(m[:fstype])
    return 'overlay' if m[:fstype] == 'overlay'
    return 'unknown' unless src.to_s.start_with?('/dev/')

    @block.protection_of_device(src)
  end

  def to_s
    "storage behind #{@mountpoint}"
  end
  alias inspect to_s
end
