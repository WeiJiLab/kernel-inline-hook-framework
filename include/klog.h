#ifndef __K_LOG_H__
#define __K_LOG_H__

#define __KLOG_TOSTRING(x)        #x
#define _KLOG_TOSTRING(x)         __KLOG_TOSTRING(x)

#define writelog(level, fmt...)        \
    printk(level __BASE_FILE__ ":" _KLOG_TOSTRING(__LINE__)" - " fmt)

#define writelog_on(condition, level, fmt...) do \
{                                                \
    if (condition) writelog(level, fmt);         \
} while (0)

#define logdebug(fmt...)        writelog(KERN_DEBUG, fmt)
#define loginfo(fmt...)         writelog(KERN_INFO, fmt)
#define logerror(fmt...)        writelog(KERN_ERR, fmt)
#define logwarn(fmt...)         writelog(KERN_WARNING, fmt)

#define logdebug_on(condition, fmt...)    writelog_on((condition), KERN_DEBUG, fmt)
#define loginfo_on(condition, fmt...)     writelog_on((condition), KERN_INFO, fmt)
#define logerror_on(condition, fmt...)    writelog_on((condition), KERN_ERR, fmt)
#define logwarn_on(condition, fmt...)     writelog_on((condition), KERN_WARNING, fmt)

#endif