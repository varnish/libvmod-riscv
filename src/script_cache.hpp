#pragma once
#include <vector>
#include <stdexcept>

template <typename T>
struct Cache {
	struct Entry {
		T*       item   = nullptr;
		uint32_t hash = 0;
		bool     non_owned = false;
	};

	T* get(size_t idx) {
		return cache.at(idx).item;
	}
	int find(uint32_t hash) {
		for (unsigned idx = 0; idx < size(); idx++) {
			if (cache[idx].hash == hash) return idx;
		}
		return -1;
	}
	size_t manage(T* ptr, uint32_t hash)
	{
		if (size() < max_size())
		{
			cache.at(size()) = { ptr, hash };
			m_size++;
			return size() - 1;
		}
		throw std::out_of_range("Too many cached items");
	}
	void free(size_t idx)
	{
		cache.at(idx) = { nullptr, 0 };
	}
	size_t size() const { return m_size; }
	size_t max_size() const { return m_max_entries; }

	void loan_from(const Cache& source) {
		/* Load the items of the source and make them non-owned */
		for (unsigned idx = 0; idx < source.size(); idx++) {
			auto& entry = source.cache[idx];
			if (entry.item) {
				if (size() >= max_size())
					throw std::out_of_range("Too many cached items");
				auto& dst = cache.at(size());
				dst = { entry.item, entry.hash };
				dst.non_owned = true;
				m_size++;
			}
		}
	}
	void foreach_owned(std::function<void(Entry&)> callback) {
		/* Load the items of the source and make them non-owned */
		for (unsigned idx = 0; idx < size(); idx++) {
			auto& entry = cache[idx];
			if (entry.item && !entry.non_owned)
				callback(entry);
		}
	}

	static constexpr size_t CACHE_MAX = 16;
	Cache(size_t max) : m_max_entries(std::min(max, CACHE_MAX)) {}

	unsigned m_size = 0;
	const unsigned m_max_entries;
	std::array<Entry, CACHE_MAX> cache;
};
