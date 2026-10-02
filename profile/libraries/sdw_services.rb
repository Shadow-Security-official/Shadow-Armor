# frozen_string_literal: true

# Running processes read from /proc (no dependency on ps): pid, owner, name
# and full command line. Service probes use it to find what really runs,
# with which options and as which user.
class ::SdwProcs < Inspec.resource(1)
  name 'sdw_procs'
  desc 'Processes running now, with owner and command line.'
  example "sdw_procs.named('nginx').map { |p| p[:user] }"

  include SdwHelpers

  SEP = "\x01"

  # [{ pid:, uid:, user:, comm:, args: [...] }]
  def all
    SdwMemo.fetch(:procs) do
      script = 'for d in /proc/[0-9]*; do [ -r "$d/cmdline" ] || continue; ' \
               'u=$(stat -c %u "$d" 2>/dev/null) || continue; c=$(cat "$d/comm" 2>/dev/null); ' \
               'a=$(tr "\\000" "\\001" < "$d/cmdline" 2>/dev/null); ' \
               'printf "%s\\t%s\\t%s\\t%s\\n" "${d#/proc/}" "$u" "$c" "$a"; done'
      users = passwd
      (cmd_ok(script) || '').lines.filter_map do |l|
        pid, uid, comm, args = l.chomp.split("\t", 4)
        next if args.to_s.empty?

        { pid: pid.to_i, uid: uid.to_i, user: users[uid.to_i] || uid, comm: comm.to_s, args: args.split(SEP) }
      end
    end
  end

  # Processes whose name (comm) is one of names.
  def named(*names)
    all.select { |p| names.flatten.include?(p[:comm]) }
  end

  # Processes whose command line matches re.
  def matching(re)
    all.select { |p| p[:args].join(' ') =~ re }
  end

  def to_s
    'running processes'
  end

  private

  def passwd
    (read_file('/etc/passwd') || '').lines.to_h do |l|
      f = l.split(':')
      [f[2].to_i, f[0]]
    end
  end
end
