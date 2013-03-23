#pragma once
#define _cleanup_free_ __attribute__((cleanup(free)))
#define _cleanup_close_ __attribute__((cleanup(close)))
