.include "macros.S"

# Kernel Version 17511

# ============================================================================
#	XamExecuteChallenge
#       nop out MmGetPhysicalAddress (so we can access salt ptr)
# ============================================================================
	MAKEPATCH 0x816799E4
0:
	nop
9:

# ============================================================================
#	XamUserCheckPrivilege
#       spoof user privilage
# ============================================================================
	MAKEPATCH 0x816DD470
0:
	li   %r11, 1
9:
	MAKEPATCH 0x816DD4E4
0:
	li   %r11, 1
9:
	MAKEPATCH 0x816DD4DC
0:
	li   %r11, 1
9:

# ============================================================================
#	XamUserGetMembershipTier
#       spoof user membership tier
# ============================================================================
MAKEPATCH 0x816DA92C
0:
	li   %r3, 6
9:

# ============================================================================
#	XamUserGetMembershipTierFromXUID
#       spoof user membership tier
# ============================================================================
MAKEPATCH 0x816DA988
0:
	li   %r3, 6
9:

# ============================================================================
#	XamGetMemberShipTier
#       spoof user membership tier
# ============================================================================
MAKEPATCH 0x81A3B998
0:
	li   %r3, 1
9:


.long 0xFFFFFFFF
