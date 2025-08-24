from datetime import datetime, time


def get_current_time() -> time:

    _data: datetime = datetime.now()
    return time(_data.hour, _data.minute, _data.second)
