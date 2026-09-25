# frozen_string_literal: true

# One pass over every local filesystem, collecting everything the file
# hygiene controls need (world-writable files, non-sticky writable dirs,
# unowned files, setuid/setgid binaries). Walking the disk once instead of four
# times matters on large hosts. Disable with the input sdw_fs_scan: false.
class ::SdwFsScan < Inspec.resource(1)
  name 'sdw_fs_scan'
  desc 'Single-pass scan of local filesystems for permission hygiene.'
  example "describe sdw_fs_scan do\n  its('world_writable_files') { should be_empty }\nend"

  include SdwHelpers

  LIMIT = 500
  LOCAL_FS = %w[ext2 ext3 ext4 xfs btrfs zfs f2fs jfs reiserfs overlay tmpfs vfat].freeze
  # Pseudo filesystems, and the storage of containers and VMs: their files
  # belong to the guests, which are audited (and fixed) on their own.
  SKIP = %w[/proc /sys /dev /run /snap /var/lib/docker /var/lib/containers /var/lib/containerd
            /var/lib/kubelet /var/lib/rancher /var/lib/lxc /var/lib/lxd /var/snap/lxd /var/lib/incus
            /var/lib/machines /var/lib/libvirt /var/lib/vz].freeze
  # Proxmox VE container volumes (subvol-<vmid>-disk-<n>).
  GUEST_VOLUME = %r{/subvol-\d+-disk-\d+(\z|/)}.freeze

  def self.skip?(path)
    SKIP.any? { |s| path == s || path.start_with?("#{s}/") } || path.match?(GUEST_VOLUME)
  end

  def mounts
    SdwMount.table(self).select { |target, m| LOCAL_FS.include?(m[:fstype]) && !self.class.skip?(target) }.keys.sort
  end

  def world_writable_files
    rows('WWF')
  end

  def world_writable_dirs_without_sticky
    rows('WWD')
  end

  def unowned
    rows('UNO')
  end

  # [{path:, mode:, owner:}]
  def setid_files
    rows('SID').map do |r|
      mode, owner, path = r.split("\t", 3)
      { path: path, mode: mode, owner: owner }
    end
  end

  def setid_not_in(allowlist)
    setid_files.reject { |f| allowlist.include?(f[:path]) || allowlist.include?(File.basename(f[:path])) }.map { |f| "#{f[:path]} (#{f[:mode]} #{f[:owner]})" }
  end

  def to_s
    'filesystem scan'
  end

  private

  def rows(tag)
    data[tag] || []
  end

  def data
    SdwMemo.fetch(:fs_scan) do
      res = Hash.new { |h, k| h[k] = [] }
      targets = mounts
      targets = ['/'] if targets.empty?
      prune = (SKIP.map { |s| "-path #{s}" } + ["-regex '.*/subvol-[0-9]+-disk-[0-9]+'"]).join(' -o ')
      expr = "\\( #{prune} \\) -prune -o " \
             "\\( -type f -perm -0002 -printf 'WWF\\t%p\\n' \\) , " \
             "\\( -type d -perm -0002 ! -perm -1000 -printf 'WWD\\t%p\\n' \\) , " \
             "\\( \\( -nouser -o -nogroup \\) -printf 'UNO\\t%p\\n' \\) , " \
             "\\( -type f \\( -perm -4000 -o -perm -2000 \\) -printf 'SID\\t%m\\t%u\\t%p\\n' \\)"
      cmd = targets.map { |t| "find #{Shellwords.escape(t)} -xdev #{expr} 2>/dev/null" }.join('; ')
      out = sh("#{cmd}; true").stdout.to_s
      out.each_line do |l|
        tag, rest = l.chomp.split("\t", 2)
        next unless rest

        res[tag] << rest if res[tag].size < LIMIT
      end
      res.each_value(&:uniq!)
      res
    end
  end
end

# Permission check over a glob of files: which ones exceed a maximum mode or
# have the wrong owner/group.
class ::SdwPerms < Inspec.resource(1)
  name 'sdw_perms'
  desc 'Files matching a glob whose mode exceeds a maximum or whose ownership is wrong.'
  example "describe sdw_perms('/etc/ssh/ssh_host_*_key', max: '0600', owner: 'root') do\n  its('violations') { should be_empty }\nend"

  include SdwHelpers

  # InSpec passes resource options as a trailing positional hash.
  def initialize(glob, opts = {})
    @glob = glob
    @max = opts.fetch(:max).to_s.to_i(8)
    @owner = opts[:owner]
    @groups = opts[:groups] && Array(opts[:groups])
  end

  def files
    dir = File.dirname(@glob)
    base = File.basename(@glob)
    base =~ /[*?\[]/ ? list_dir(dir, base) : (inspec.file(@glob).exist? ? [@glob] : [])
  end

  def violations
    files.flat_map do |f|
      st = inspec.file(f)
      next [] if st.symlink?

      v = []
      extra = st.mode & ~@max & 0o7777
      v << "#{f}: mode #{format('%04o', st.mode)} (max #{format('%04o', @max)})" if extra != 0
      v << "#{f}: owner #{st.owner}" if @owner && st.owner != @owner
      v << "#{f}: group #{st.group}" if @groups && !@groups.include?(st.group)
      v
    end
  end

  def to_s
    "permissions of #{@glob} (max #{format('%04o', @max)})"
  end
end

# Secrets at rest: private keys and credential files that other users can read.
class ::SdwSecrets < Inspec.resource(1)
  name 'sdw_secrets'
  desc 'Private keys and credential files readable beyond their owner.'
  example "describe sdw_secrets do\n  its('private_key_problems') { should be_empty }\nend"

  include SdwHelpers

  KEY_DIRS = %w[/etc/ssl/private /etc/pki/tls/private /etc/letsencrypt/archive /etc/letsencrypt/keys].freeze
  USER_SECRETS = %w[.pgpass .my.cnf .netrc .git-credentials .aws/credentials .kube/config .docker/config.json .vault-token].freeze

  def private_key_problems
    SdwMemo.fetch(:private_keys) do
      probs = []
      KEY_DIRS.each do |d|
        st = inspec.file(d)
        next unless st.exist? && st.directory?

        probs << "#{d}: directory mode #{format('%04o', st.mode)} (other has access)" if (st.mode & 0o007) != 0
      end
      # Content-based: any *.key / *.pem under /etc holding a private key and readable by other.
      out = cmd_ok("find /etc -xdev -type f \\( -name '*.key' -o -name '*.pem' \\) -perm -004 -exec grep -l 'PRIVATE KEY' {} + 2>/dev/null").to_s
      out.lines.map(&:strip).reject(&:empty?).first(100).each { |f| probs << "#{f}: private key readable by other" }
      probs
    end
  end

  def user_secret_problems
    SdwMemo.fetch(:user_secrets) do
      probs = []
      inspec.sdw_accounts.interactive_users.each do |u|
        home = u[:home].to_s
        next unless home.start_with?('/') && home != '/'

        names = USER_SECRETS.map { |s| s.include?('/') ? "-path '#{home}/#{s}'" : "-path '#{home}/#{s}'" }.join(' -o ')
        cmd = "find #{Shellwords.escape(home)} -maxdepth 3 \\( -path '#{home}/.ssh' -o -path '#{home}/.ssh/*' -o #{names} \\) -printf '%m\\t%y\\t%p\\n' 2>/dev/null"
        cmd_ok(cmd).to_s.each_line do |l|
          mode, type, path = l.chomp.split("\t", 3)
          next unless path

          m = mode.to_i(8)
          base = File.basename(path)
          if type == 'd' && path.end_with?('/.ssh')
            probs << "#{path}: mode #{mode} (expected 700)" if (m & 0o077) != 0
          elsif path.include?('/.ssh/')
            next if base.end_with?('.pub') || base == 'known_hosts' || base.start_with?('known_hosts')

            if %w[authorized_keys authorized_keys2 config].include?(base)
              probs << "#{path}: writable by group/other (#{mode})" if (m & 0o022) != 0
            elsif type == 'f' && (m & 0o077) != 0
              probs << "#{path}: private material readable by group/other (#{mode})"
            end
          elsif type == 'f' && (m & 0o077) != 0
            probs << "#{path}: credentials readable by group/other (#{mode})"
          end
        end
      end
      probs
    end
  end

  def to_s
    'secrets at rest'
  end
end
