# shadow_armor cookbook

Interpreter for the declarative remediation plans produced by `sdw-armor harden`.
It is embedded in the `sdw-armor` binary and converged with `cinc-client --local-mode`;
you normally never run it by hand.

* Input: `node['shadow_armor']['actions']`, a list of `{control, kind, ...}` actions
  taken from `profile/files/catalog.json`.
* Every action kind maps to native Chef resources (`file`, `package`, `execute` with
  guards...), so `--why-run` shows what would change and every edited file is backed up
  in `file_backup_path` (`/var/lib/shadow-armor/backup` when run by sdw-armor).
* Shadow-Armor prefers its own drop-in files (`00-shadow-armor.conf`,
  `99-zz-shadow-armor.conf`, `60-shadow-armor.*`, `zz-shadow-armor`) over editing
  vendor files; deleting them reverts the corresponding settings.
* A journal of each run is written to `/var/lib/shadow-armor/journal/<run_id>.json`.

To review it: `sdw-armor export cookbook ./shadow_armor`.
