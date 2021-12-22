rule yaraeicar   {
    meta:
      author="methane4"
      description="eicar test yara"
    strings:
      $a="X5O"
      $b="EICAR"
      $c="ANTIVIRUS"
      $d="TEST"
    condition:
      $a and $b and $c and $d
  }
