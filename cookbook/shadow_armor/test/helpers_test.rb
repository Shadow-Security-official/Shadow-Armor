# frozen_string_literal: true

# Unit tests of the cookbook's text transformations (plain Ruby, no Chef):
#   ruby cookbook/shadow_armor/test/helpers_test.rb
require 'minitest/autorun'
require 'tmpdir'
require_relative '../libraries/helpers'

class HelpersTest < Minitest::Test
  H = ShadowArmor::Helpers

  def with_file(content)
    Dir.mktmpdir do |d|
      f = File.join(d, 'f.conf')
      File.write(f, content)
      yield f, d
    end
  end

  # A second harden run must keep what the first one wrote.
  def test_owned_files_merge_across_runs
    with_file("# Managed by Shadow-Armor (sdw-armor harden) - controls: SA-01.02\nkernel.randomize_va_space = 2\nnet.ipv4.ip_forward = 0\n") do |f, _|
      assert_equal({ 'kernel.randomize_va_space' => '2', 'net.ipv4.ip_forward' => '1', 'kernel.sysrq' => '0' },
                   H.merged_settings(f, { 'net.ipv4.ip_forward' => '1', 'kernel.sysrq' => '0' }, sep: '='))
      assert_equal ['SA-01.02'], H.managed_controls(f)
    end
    with_file("# h\nPermitRootLogin no\nmaxauthtries 6\n") do |f, _|
      assert_equal({ 'PermitRootLogin' => 'no', 'MaxAuthTries' => '4' }, H.merged_settings(f, { 'MaxAuthTries' => 4 }, sep: ' ', casefold: true))
      assert_equal ['PermitRootLogin no', 'maxauthtries 6', 'X y'], H.merged_lines(f, ['PermitRootLogin no', 'X y'])
    end
    Dir.mktmpdir { |d| assert_equal({ 'a' => '1' }, H.merged_settings(File.join(d, 'none'), { 'a' => 1 }, sep: '=')) }
  end

  def test_kv_transform
    assert_equal "A 5\n#B 2\nC 3\n# A 9 (superseded by Shadow-Armor)\nB 7\n", H.kv_transform("A 1\n#B 2\nC 3\nA 9\n", { 'A' => '5', 'B' => '7' }, ' ')
    assert_equal "minlen = 8\nenforce_for_root\n", H.kv_transform("minlen = 8\n", { 'enforce_for_root' => '' }, '')
  end

  def test_fstab_grub_ini_lines
    assert_equal "UUID=x\t/tmp\text4\tnodev,nosuid\t0\t2\n/dev/a / ext4 defaults 0 1\n",
                 H.fstab_transform("UUID=x /tmp ext4 defaults 0 2\n/dev/a / ext4 defaults 0 1\n", '/tmp', %w[nodev nosuid])
    assert_equal %(GRUB_CMDLINE_LINUX="quiet audit=1"\n), H.grub_default_transform(%(GRUB_CMDLINE_LINUX="quiet audit=0"\n), { 'audit' => '1' })
    assert_equal "[commands]\nupgrade_type = security\napply_updates = yes\n[emitters]\nx = 1\n",
                 H.ini_transform("[commands]\nupgrade_type = default\n[emitters]\nx = 1\n", 'commands', { 'upgrade_type' => 'security', 'apply_updates' => 'yes' })
    assert_equal 'Include x', H.line_transform("Port 22\n", 'Include x', first: true).lines.first.chomp
    assert_equal "auth sufficient pam_rootok.so\nauth required pam_wheel.so\nauth x\n",
                 H.line_transform("auth sufficient pam_rootok.so\nauth x\n", 'auth required pam_wheel.so', after: '^auth\s+sufficient\s+pam_rootok')
  end

  def test_sysctl_conf_conflicts_are_commented
    assert_equal "# kernel.sysrq = 1  # superseded by /etc/sysctl.d/99-zz-shadow-armor.conf\n# kernel.sysrq = 1\nvm.x = 2\n",
                 H.sysctl_conf_transform("kernel.sysrq = 1\n# kernel.sysrq = 1\nvm.x = 2\n", { 'kernel.sysrq' => '0' })
  end

  def test_weak_hash
    assert H.weak_hash?('$1$abc$def')
    refute H.weak_hash?('$6$x$y')
    refute H.weak_hash?('$y$j9T$a$b')
    refute H.weak_hash?('!')
  end

  def test_root_login_never_relaxed
    assert_equal 'no', H.stricter_root_login('prohibit-password', 'no')
    assert_equal 'prohibit-password', H.stricter_root_login('prohibit-password', 'yes')
    assert_equal 'prohibit-password', H.stricter_root_login('prohibit-password', nil)
    assert_equal 'no', H.stricter_root_login('no', 'without-password')
  end

  def test_expires_at_once
    today = H.today
    refute H.expires_at_once?({ last: (today - 10).to_s }, 365)
    assert H.expires_at_once?({ last: (today - 400).to_s }, 365)
    refute H.expires_at_once?({ last: (today - 400).to_s }, 365, 45)
    assert H.expires_at_once?({ last: (today - 420).to_s }, 365, 45)
    assert H.expires_at_once?({ last: '0' }, 365)
    refute H.expires_at_once?({ last: '' }, 365)
  end

  def test_guest_storage_is_skipped
    assert H.scan_skip?('/var/lib/docker/overlay2/x')
    assert H.scan_skip?('/rpool/data/subvol-101-disk-0')
    assert H.scan_skip?('/var/lib/lxc/101/rootfs/etc')
    refute H.scan_skip?('/srv/www/images/2024')
    refute H.scan_skip?('/var/lib/dockerish')
  end

  def test_listening_ports
    ss = <<~SS
      tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
      tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=2,fd=3))
      tcp LISTEN 0 128 [::]:443 [::]:* users:(("nginx",pid=3,fd=3))
      udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*
      udp UNCONN 0 0 *:58485 *:* users:(("cloudflared",pid=4,fd=9))
      udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("named",pid=5,fd=9))
    SS
    assert_equal %w[22/tcp 53/udp 443/tcp 51820/udp], H.listening_ports(ss)
  end
end
