# frozen_string_literal: true

# Pure text transformations and host queries used by the recipe. Everything
# that edits a file returns the new content: the recipe hands it to a native
# `file` resource, so Chef shows a diff, honours why-run and keeps a backup.
module ShadowArmor
  module Helpers
    MARK = 'Managed by Shadow-Armor'
    NOLOGIN = %r{(/nologin|/false|/sync|/shutdown|/halt)\z}.freeze

    module_function

    def read(path)
      ::File.exist?(path) ? ::File.read(path) : nil
    end

    def header(controls)
      "# #{MARK} (sdw-armor harden) - controls: #{Array(controls).uniq.sort.join(', ')}\n# Remove this file to revert these settings.\n"
    end

    # ---- owned files are merged across runs --------------------------------
    # A second `harden` run must add to what the first one wrote, never drop it.

    # Controls listed in the header of a file we own.
    def managed_controls(path)
      read(path).to_s[/controls: ([^\n]*)/, 1].to_s.split(',').map(&:strip).reject(&:empty?)
    end

    def body_lines(path)
      read(path).to_s.lines.map(&:chomp).reject { |l| l.strip.empty? || l.strip.start_with?('#') }
    end

    # "Key value" (sshd) or "key = value" (sysctl) files: existing keys kept,
    # new values win. Keys compare case-insensitively for sshd.
    def merged_settings(path, settings, sep:, casefold: false)
      out = {}
      body_lines(path).each do |l|
        k, v = sep == ' ' ? l.strip.split(/\s+/, 2) : l.split('=', 2).map(&:strip)
        next unless k && v

        out[k] = v
      end
      settings.each do |k, v|
        out.delete(out.keys.find { |x| casefold ? x.casecmp?(k) : x == k })
        out[k] = v.to_s
      end
      out
    end

    def merged_lines(path, lines)
      (body_lines(path) + Array(lines)).uniq
    end

    # [Section] KEY=VALUE drop-in: merge keys of the one section we write.
    def merged_ini(path, settings)
      out = {}
      body_lines(path).each do |l|
        next if l.start_with?('[')

        k, v = l.split('=', 2)
        out[k.strip] = v.to_s.strip if v
      end
      out.merge(settings.transform_values(&:to_s))
    end

    # Sets KEY<sep>VALUE lines in a key/value file (login.defs, auditd.conf,
    # pwquality.conf...). Existing active lines are replaced in place, commented
    # templates are left alone, missing keys are appended.
    def kv_transform(text, settings, sep)
      lines = text.to_s.lines.map(&:chomp)
      settings.each do |key, value|
        line = sep.to_s.empty? ? key.to_s : "#{key}#{sep}#{value}"
        re = /\A\s*#{Regexp.escape(key)}(\s|=|\z)/
        idx = lines.index { |l| l =~ re }
        if idx
          lines[idx] = line
          # Later duplicates would win for some parsers: comment them.
          lines.each_with_index { |l, i| lines[i] = "# #{l} (superseded by Shadow-Armor)" if i > idx && l =~ re }
        else
          lines << line
        end
      end
      "#{lines.join("\n")}\n"
    end

    # INI-style edit restricted to one [section] (dnf automatic.conf).
    def ini_transform(text, section, settings)
      lines = text.to_s.lines.map(&:chomp)
      settings.each do |key, value|
        cur = nil
        idx = nil
        sec_end = nil
        lines.each_with_index do |l, i|
          if (m = l.strip.match(/\A\[(.+)\]\z/))
            sec_end = i if cur == section && sec_end.nil?
            cur = m[1]
            next
          end
          idx = i if cur == section && l =~ /\A\s*#{Regexp.escape(key)}\s*=/
        end
        if idx
          lines[idx] = "#{key} = #{value}"
        elsif lines.any? { |l| l.strip == "[#{section}]" }
          at = sec_end || lines.size
          lines.insert(at, "#{key} = #{value}")
        else
          lines << "[#{section}]" << "#{key} = #{value}"
        end
      end
      "#{lines.join("\n")}\n"
    end

    # Adds or replaces one line: replace the line matching `match`, else insert
    # after the line matching `after`, at the top (`first`), or at the end.
    def line_transform(text, line, match: nil, after: nil, first: false)
      lines = text.to_s.lines.map(&:chomp)
      return "#{lines.join("\n")}\n" if lines.include?(line)

      if match && (idx = lines.index { |l| l =~ Regexp.new(match) })
        lines[idx] = line
      elsif after && (idx = lines.index { |l| l =~ Regexp.new(after) })
        lines.insert(idx + 1, line)
      elsif first
        lines.unshift(line, "# ^ #{MARK}: must stay first (sshd/ssh keep the first value they read)")
      else
        lines << line
      end
      "#{lines.join("\n")}\n"
    end

    # Comments assignments of keys we manage in /etc/sysctl.conf, which
    # `sysctl --system` applies last and would otherwise override our drop-in.
    def sysctl_conf_transform(text, settings)
      text.to_s.lines.map do |l|
        k, v = l.split('=', 2)
        key = k.to_s.strip.sub(/\A-/, '').tr('/', '.')
        if v && !l.strip.start_with?('#', ';') && settings.key?(key) && v.strip != settings[key].to_s
          "# #{l.chomp}  # superseded by /etc/sysctl.d/99-zz-shadow-armor.conf\n"
        else
          l
        end
      end.join
    end

    # Adds mount options to the fstab entry of a mount point.
    def fstab_transform(text, mountpoint, add)
      text.to_s.lines.map do |l|
        f = l.split
        if !l.strip.start_with?('#') && f[1] == mountpoint && f.size >= 4
          opts = f[3].split(',') - ['defaults']
          opts = (opts + add).uniq
          f[3] = opts.join(',')
          f << '0' while f.size < 6
          "#{f.join("\t")}\n"
        else
          l
        end
      end.join
    end

    def fstab_has?(mountpoint)
      read('/etc/fstab').to_s.lines.any? { |l| !l.strip.start_with?('#') && l.split[1] == mountpoint }
    end

    def mounted?(mountpoint)
      read('/proc/self/mounts').to_s.lines.any? { |l| l.split[1] == mountpoint }
    end

    def current_mount_options(mountpoint)
      l = read('/proc/self/mounts').to_s.lines.find { |x| x.split[1] == mountpoint }
      l ? l.split[3].split(',') : []
    end

    # Adds KEY=VALUE to GRUB_CMDLINE_LINUX in /etc/default/grub.
    def grub_default_transform(text, params)
      lines = text.to_s.lines.map(&:chomp)
      idx = lines.index { |l| l =~ /\A\s*GRUB_CMDLINE_LINUX=/ }
      lines << 'GRUB_CMDLINE_LINUX=""' unless idx
      idx ||= lines.size - 1
      cur = lines[idx].split('=', 2).last.strip.delete_prefix('"').delete_suffix('"').split
      params.each do |k, v|
        cur.reject! { |t| t.split('=', 2).first == k }
        cur << (v.to_s.empty? ? k : "#{k}=#{v}")
      end
      lines[idx] = %(GRUB_CMDLINE_LINUX="#{cur.join(' ')}")
      "#{lines.join("\n")}\n"
    end

    def passwd_entries
      read('/etc/passwd').to_s.lines.filter_map do |l|
        f = l.chomp.split(':', -1)
        next if f.size < 7

        { name: f[0], uid: f[2].to_i, gid: f[3].to_i, home: f[5], shell: f[6] }
      end
    end

    def shadow_entries
      read('/etc/shadow').to_s.lines.to_h do |l|
        f = l.chomp.split(':', -1)
        [f[0], { hash: f[1].to_s, last: f[2], min: f[3], max: f[4], warn: f[5], inactive: f[6] }]
      end
    end

    def uid_min
      v = read('/etc/login.defs').to_s[/^\s*UID_MIN\s+(\d+)/, 1]
      (v || 1000).to_i
    end

    def interactive_users
      passwd_entries.select do |u|
        (u[:uid] >= uid_min || u[:uid].zero?) && u[:shell] !~ NOLOGIN && !u[:shell].empty? && u[:name] != 'nobody'
      end
    end

    def today
      Time.now.to_i / 86_400
    end

    # Would a maximum password age of max_days (plus an inactivity period)
    # expire, or disable, this account the moment it is applied?
    def expires_at_once?(entry, max_days, inactive = 0)
      last = entry[:last].to_s
      return false if last.empty?
      return true if last.to_i.zero? # already flagged "change at next login"

      last.to_i + max_days.to_i + inactive.to_i < today
    end

    # Users that own a crontab in the spool (Debian and RHEL layouts).
    def crontab_users
      %w[/var/spool/cron/crontabs /var/spool/cron].flat_map do |d|
        next [] unless ::File.directory?(d)

        Dir.children(d).select { |f| ::File.file?(::File.join(d, f)) }
      end.uniq.sort
    end

    def authorized_keys?(home)
      %w[authorized_keys authorized_keys2].any? { |f| ::File.size?(::File.join(home.to_s, '.ssh', f)) }
    end

    # PermitRootLogin values from the most to the least restrictive: merging
    # two runs must never relax what an earlier one set.
    ROOT_LOGIN_ORDER = %w[no forced-commands-only prohibit-password without-password yes].freeze

    def stricter_root_login(a, b)
      [a, b].compact.min_by { |v| ROOT_LOGIN_ORDER.index(v.to_s.downcase) || ROOT_LOGIN_ORDER.size }
    end

    # Ports reachable from the network now, as "port/proto". UDP sockets on an
    # ephemeral port that belong to a process are client sockets, left out.
    def listening_ports(ss_output = `ss -H -tulnp 2>/dev/null`)
      lo, hi = read('/proc/sys/net/ipv4/ip_local_port_range').to_s.split.map(&:to_i)
      eph = lo.to_i.positive? ? (lo..hi) : (32_768..60_999)
      ss_output.to_s.lines.filter_map do |l|
        f = l.split
        next if f.size < 5

        addr, _, port = f[4].rpartition(':')
        addr = addr.delete_prefix('[').delete_suffix(']').sub(/%.*\z/, '')
        next if addr =~ /\A(127\.|::1\z|::ffff:127\.)/ || port.to_i.zero?
        next if f[0] == 'udp' && eph.cover?(port.to_i) && l.include?('users:(')

        "#{port.to_i}/#{f[0]}"
      end.uniq.sort_by(&:to_i)
    end

    def usable_password?(hash)
      !(hash.empty? || hash.start_with?('!', '*'))
    end

    def weak_hash?(hash)
      h = hash.delete_prefix('!').delete_prefix('!')
      return false if h.empty? || h.start_with?('*', '!') || h == 'x'

      h !~ /\A\$(6|y|gy|7|2b|2y|2a)\$/
    end

    def nologin_shell
      %w[/usr/sbin/nologin /sbin/nologin /usr/bin/nologin].find { |s| ::File.executable?(s) } || '/bin/false'
    end

    def which(bin)
      ENV.fetch('PATH', '/usr/sbin:/usr/bin:/sbin:/bin').split(':').push('/usr/sbin', '/sbin').each do |d|
        p = ::File.join(d, bin)
        return p if ::File.executable?(p)
      end
      nil
    end

    def systemd?
      ::File.directory?('/run/systemd/system')
    end

    def unit_exists?(unit)
      return false if which('systemctl').nil?

      out = `systemctl show -p LoadState --value #{unit} 2>/dev/null`.strip
      return !out.empty? && out != 'not-found' if $?.success? && systemd?

      %w[/etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system].any? { |d| ::File.exist?(::File.join(d, unit)) }
    end

    def package_installed?(name)
      if which('dpkg-query')
        `dpkg-query -W -f='${db:Status-Abbrev}' #{name} 2>/dev/null`.start_with?('ii')
      elsif which('rpm')
        system("rpm -q #{name} >/dev/null 2>&1")
      else
        false
      end
    end

    # Recommended algorithm list filtered to what this OpenSSH supports.
    def ssh_supported(kind, prefer)
      q = { 'cipher' => 'cipher', 'mac' => 'mac', 'kex' => 'kex' }.fetch(kind)
      supported = `ssh -Q #{q} 2>/dev/null`.split
      supported = `sshd -Q #{q} 2>/dev/null`.split if supported.empty?
      return prefer if supported.empty?

      prefer.select { |a| supported.include?(a) }
    end

    def openssh_version
      out = `ssh -V 2>&1`
      m = out.match(/OpenSSH_(\d+)\.(\d+)/)
      m ? [m[1].to_i, m[2].to_i] : [0, 0]
    end

    # Pseudo filesystems and guest storage (containers, VMs), skipped like the
    # audit does: a guest's files are fixed by hardening the guest itself.
    SCAN_SKIP = %w[/proc /sys /dev /run /snap /var/lib/docker /var/lib/containers /var/lib/containerd
                   /var/lib/kubelet /var/lib/rancher /var/lib/lxc /var/lib/lxd /var/snap/lxd /var/lib/incus
                   /var/lib/machines /var/lib/libvirt /var/lib/vz].freeze
    GUEST_VOLUME = %r{/subvol-\d+-disk-\d+(\z|/)}.freeze

    def scan_skip?(path)
      SCAN_SKIP.any? { |s| path == s || path.start_with?("#{s}/") } || path.match?(GUEST_VOLUME)
    end

    # Directories to scan for world-writable files, like the audit does.
    def local_mounts
      fs = %w[ext2 ext3 ext4 xfs btrfs zfs f2fs jfs reiserfs overlay tmpfs vfat]
      read('/proc/self/mounts').to_s.lines.filter_map do |l|
        _, t, type = l.split
        t if fs.include?(type) && !scan_skip?(t)
      end.uniq
    end

    def find_paths(expr)
      skip = (SCAN_SKIP.map { |s| "-path #{s}" } + ["-regex '.*/subvol-[0-9]+-disk-[0-9]+'"]).join(' -o ')
      local_mounts.flat_map do |m|
        `find #{m} -xdev \\( #{skip} \\) -prune -o #{expr} -print 2>/dev/null`.lines.map(&:chomp)
      end.uniq.reject { |p| scan_skip?(p) }
    end
  end
end
