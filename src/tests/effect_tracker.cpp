#include <dynohook/tests/effect_tracker.h>

using namespace dyno;

Effect::Effect() : m_executed{0}, m_uid{s_counter++} {
}

void Effect::trigger() {
    ++m_executed;
}

bool Effect::didExecute(size_t n) const {
    return m_executed == n;
}

void EffectTracker::push() {
    m_queue.emplace_back();
}

Effect EffectTracker::pop() {
    Effect effect = m_queue.back();
    m_queue.pop_back();
    return effect;
}

Effect& EffectTracker::peak() {
    if (m_queue.empty())
        return m_queue.emplace_back();
    else
        return m_queue.back();
}