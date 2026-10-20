import 'dart:convert';

import 'package:flet/flet.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

const MethodChannel _channel = MethodChannel('dev.cipher/native');

/// Invisible control that forwards Flet method calls to the Android plugin.
///
/// The Dart side performs no cryptography and keeps no state beyond the
/// mounted control.  Every response is a JSON object so Python can distinguish
/// "channel unavailable" from "operation failed" without parsing error text.
class CipherNativeControl extends StatefulWidget {
  final Control? parent;
  final Control control;
  final FletControlBackend backend;

  const CipherNativeControl({
    super.key,
    required this.parent,
    required this.control,
    required this.backend,
  });

  @override
  State<CipherNativeControl> createState() => _CipherNativeControlState();
}

class _CipherNativeControlState extends State<CipherNativeControl> {
  @override
  void initState() {
    super.initState();
    _requestSecure();
  }

  @override
  void deactivate() {
    widget.backend.unsubscribeMethods(widget.control.id);
    super.deactivate();
  }

  Future<void> _requestSecure() async {
    if (defaultTargetPlatform != TargetPlatform.android) return;
    try {
      await _channel.invokeMethod<String>('setSecure', {'enabled': 'true'});
    } catch (_) {
      // The plugin's onAttachedToActivity is authoritative.  A failure here
      // means the channel is missing, which `status` reports to Python.
    }
  }

  @override
  Widget build(BuildContext context) {
    widget.backend.subscribeMethods(widget.control.id, _onMethod);
    return const SizedBox.shrink();
  }

  Future<String?> _onMethod(String methodName, Map<String, String> args) async {
    if (defaultTargetPlatform != TargetPlatform.android) {
      return jsonEncode({
        'available': false,
        'ok': false,
        'reason': 'platform_not_android',
      });
    }
    try {
      final result = await _channel.invokeMethod<String>(methodName, args);
      if (result == null) {
        return jsonEncode({
          'available': false,
          'ok': false,
          'reason': 'empty_native_result',
        });
      }
      return result;
    } on MissingPluginException {
      return jsonEncode({
        'available': false,
        'ok': false,
        'reason': 'plugin_not_registered',
      });
    } on PlatformException catch (error) {
      return jsonEncode({
        'available': true,
        'ok': false,
        'reason': error.code,
      });
    } catch (_) {
      return jsonEncode({
        'available': false,
        'ok': false,
        'reason': 'channel_error',
      });
    }
  }
}
