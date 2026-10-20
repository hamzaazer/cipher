import 'package:flet/flet.dart';

import 'cipher_native.dart';

CreateControlFactory createControl = (CreateControlArgs args) {
  switch (args.control.type) {
    case "cipher_native":
      return CipherNativeControl(
        parent: args.parent,
        control: args.control,
        backend: args.backend,
      );
    default:
      return null;
  }
};

void ensureInitialized() {
  // No global native state to set up.  The plugin applies FLAG_SECURE from
  // onAttachedToActivity, before the first Flutter frame.
}
