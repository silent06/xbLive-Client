/*==========================================================================;
 *
 *  Copyright (C) Microsoft Corporation.  All Rights Reserved.
 *
 *  File:       XamXui.h
 *  Content:    Xbox 360 UI main header (modified for Xam)
 *
 ****************************************************************************/

// the headers in this group do not depend on each other and the order
// of inclusion among the headers in the group can be changed arbitrarily
#include "XamXuiResource.h"
#include "XamXuiError.h"
#include "XamXuiMemory.h"

// these headers depend on xuimemory.h
// the headers in this group do not depend on each other and the order
// of inclusion among the headers in the group can be changed arbitrarily
#include "XamXuiRender.h"
#include "XamXuiBase.h"

// these headers depend on at least one of the headers above
// the headers in this group do not depend on each other and the order
// of inclusion among the headers in the group can be changed arbitrarily
#include "XamXuiMessage.h"
#include "XamXuiAnimate.h"
#include "XamXuiAudition.h"

// this header depends on at least one of the headers above
#include "XamXuiElement.h"