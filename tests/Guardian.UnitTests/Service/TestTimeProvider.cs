namespace Guardian.UnitTests.Service;

internal sealed class TestTimeProvider : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<TestTimer> _timers = [];
    private DateTimeOffset _utcNow;

    public TestTimeProvider(DateTimeOffset? initialUtcNow = null)
    {
        _utcNow = initialUtcNow ?? new DateTimeOffset(2026, 11, 27, 0, 0, 0, TimeSpan.Zero);
    }

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
        {
            return _utcNow;
        }
    }

    public override long GetTimestamp() => GetUtcNow().UtcTicks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public int ActiveTimerCount
    {
        get
        {
            lock (_gate)
            {
                return _timers.Count;
            }
        }
    }

    public void Advance(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(delta));
        }

        List<(TimerCallback Callback, object? State)> dueCallbacks = [];

        lock (_gate)
        {
            _utcNow = _utcNow.Add(delta);

            foreach (var timer in _timers)
            {
                if (timer.TryFire(_utcNow, out var callback, out var state) && callback is not null)
                {
                    dueCallbacks.Add((callback, state));
                }
            }
        }

        foreach (var (callback, state) in dueCallbacks)
        {
            callback(state);
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        ArgumentNullException.ThrowIfNull(callback);

        lock (_gate)
        {
            var timer = new TestTimer(this, callback, state, _utcNow, dueTime, period);
            _timers.Add(timer);
            return timer;
        }
    }

    private void RemoveTimer(TestTimer timer)
    {
        lock (_gate)
        {
            _timers.Remove(timer);
        }
    }

    private sealed class TestTimer : ITimer
    {
        private readonly TestTimeProvider _owner;
        private readonly TimerCallback _callback;
        private readonly object? _state;
        private DateTimeOffset? _nextDueUtc;
        private TimeSpan _period;
        private bool _disposed;

        public TestTimer(
            TestTimeProvider owner,
            TimerCallback callback,
            object? state,
            DateTimeOffset now,
            TimeSpan dueTime,
            TimeSpan period)
        {
            _owner = owner;
            _callback = callback;
            _state = state;
            ApplySchedule(now, dueTime, period);
        }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (_owner._gate)
            {
                if (_disposed)
                {
                    return false;
                }

                ApplySchedule(_owner._utcNow, dueTime, period);
                return true;
            }
        }

        public bool TryFire(DateTimeOffset now, out TimerCallback? callback, out object? state)
        {
            if (_disposed || !_nextDueUtc.HasValue || now < _nextDueUtc.Value)
            {
                callback = null;
                state = null;
                return false;
            }

            callback = _callback;
            state = _state;
            _nextDueUtc = _period == Timeout.InfiniteTimeSpan || _period <= TimeSpan.Zero
                ? null
                : now.Add(_period);
            return true;
        }

        public void Dispose()
        {
            _disposed = true;
            _owner.RemoveTimer(this);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        private void ApplySchedule(DateTimeOffset now, TimeSpan dueTime, TimeSpan period)
        {
            _period = period;
            _nextDueUtc = dueTime == Timeout.InfiniteTimeSpan
                ? null
                : now.Add(dueTime < TimeSpan.Zero ? TimeSpan.Zero : dueTime);
        }
    }
}
