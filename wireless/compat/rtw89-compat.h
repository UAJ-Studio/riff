/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compatibility shims so mainline (7.3) rtw89 builds on the WSL 6.18 kernel.
 * Force-included into every rtw89 object by the Makefile.
 */
#ifndef __RTW89_WIFICAP_COMPAT_H
#define __RTW89_WIFICAP_COMPAT_H

#include <linux/bitfield.h>
#include <linux/ieee80211.h>
#include <net/mac80211.h>

#ifndef field_get
#define field_get(mask, reg) \
	((typeof(mask))(((reg) & (mask)) >> __builtin_ctzll(mask)))
#endif
#ifndef field_prep
#define field_prep(mask, val) \
	((typeof(mask))(((typeof(mask))(val) << __builtin_ctzll(mask)) & (mask)))
#endif
#ifndef __signed_scalar_typeof
#define __scalar_type_to_signed_cases(type)				\
		unsigned type:	(signed type)0,				\
		signed type:	(signed type)0
#define __signed_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			char:	(signed char)0,				\
			__scalar_type_to_signed_cases(char),		\
			__scalar_type_to_signed_cases(short),		\
			__scalar_type_to_signed_cases(int),		\
			__scalar_type_to_signed_cases(long),		\
			__scalar_type_to_signed_cases(long long),	\
			default: (x)))
#endif
#ifndef FIELD_GET_SIGNED
#define FIELD_GET_SIGNED(mask, reg)					\
	((__signed_scalar_typeof(mask))					\
	 (((long long)(reg) << __builtin_clzll(mask)) >>		\
	  (__builtin_clzll(mask) + __builtin_ctzll(mask))))
#endif

#ifndef IEEE80211_EML_CAP_EML_PADDING_DELAY_256US
#define IEEE80211_EML_CAP_EML_PADDING_DELAY_256US IEEE80211_EML_CAP_EMLSR_PADDING_DELAY_256US
#endif

/* mac80211 in 6.18 cannot take driver-supplied VHT radiotap; rtw89's helper
 * that fills it is turned into a no-op by the backport script. A newer
 * mac80211 (RIFF_HAVE_RADIOTAP_VHT, set by rtw89-apply.sh) has it all. */
#ifndef RIFF_HAVE_RADIOTAP_VHT
struct ieee80211_radiotap_vht {
	__le16 known;
	u8 flags;
	u8 bandwidth;
	u8 mcs_nss[4];
	u8 coding;
	u8 group_id;
	__le16 partial_aid;
} __packed;
#define RX_FLAG_RADIOTAP_VHT 0
#endif

/* for_each_station(): __ieee80211_iterate_stations() is backported into
 * net/mac80211/util.c by the build script. */
#ifndef for_each_station
struct ieee80211_sta *
__ieee80211_iterate_stations(struct ieee80211_hw *hw, struct ieee80211_sta *prev);
#define for_each_station(sta, hw)					\
	for (sta = __ieee80211_iterate_stations(hw, NULL);		\
	     sta;							\
	     sta = __ieee80211_iterate_stations(hw, sta))
#endif

#endif
