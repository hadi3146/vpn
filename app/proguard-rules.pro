# Keep Room schemas
-keep class * extends androidx.room.RoomDatabase
# Keep Dagger / Hilt
-keep class * extends com.google.dagger.hilt.android.internal.managers.ViewComponentManager
# Keep VPN models and entities
-keep class com.aethervpn.client.data.model.** { *; }
-keep class com.aethervpn.vpncore.** { *; }

