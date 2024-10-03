enum DTLSState {
  New,
  Connecting,
  Connected,
  Failed,
}

extension DTLSStateExtension on DTLSState {
  String get name {
    switch (this) {
      case DTLSState.New:
        return 'New';
      case DTLSState.Connecting:
        return 'Connecting';
      case DTLSState.Connected:
        return 'Connected';
      case DTLSState.Failed:
        return 'Failed';
      default:
        return 'Unknown';
    }
  }

  String DTLSStateToString() => name;
}
