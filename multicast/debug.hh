#ifndef MC_DEBUG_HH
#define MC_DEBUG_HH

#define CLICK_MC_DEBUG
#ifdef CLICK_MC_DEBUG
#define debug_msg(s...) click_chatter(s)
#endif
#ifndef CLICK_MC_DEBUG
#define debug_msg(s...) if(0)
#endif

#endif
