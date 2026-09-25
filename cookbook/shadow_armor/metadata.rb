name             'shadow_armor'
maintainer       'Shadow Security'
license          'Apache-2.0'
description      'Converges the declarative remediation plan produced by sdw-armor harden'
version          '0.1.0'
chef_version     '>= 16.0'

%w(ubuntu debian redhat centos rocky almalinux oracle fedora amazon).each { |os| supports os }

source_url 'https://github.com/Shadow-Security-official/Shadow-Armor'
issues_url 'https://github.com/Shadow-Security-official/Shadow-Armor/issues'
