class ssh_hardening::params {

  if !defined('$ssh_server_version_major') {
    $macs = get_ssh_macs($::operatingsystem, $::operatingsystemrelease, $weak_hmac)
  } else {
    if versioncmp($ssh_server_version_major, '5.3') <= 0 {
      $macs = 'hmac-ripemd160,hmac-sha1'
    } elsif versioncmp($ssh_server_version_major, '5.9') <= 0 {
      $macs = 'hmac-sha2-512,hmac-sha2-256,hmac-ripemd160'
    } elsif versioncmp($ssh_server_version_major, '6.6') <= 0 {
        $macs = 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160'
    } elsif versioncmp($ssh_server_version_major, '7.6') <= 0 {
        $macs = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512'
    }
  }

  $ciphers = get_ssh_ciphers($::operatingsystem, $::operatingsystemrelease, $cbc_required)
  $kex = get_ssh_kex($::operatingsystem, $::operatingsystemrelease, $weak_kex)
  $priv_sep = use_privilege_separation($::operatingsystem, $::operatingsystemrelease)

}
