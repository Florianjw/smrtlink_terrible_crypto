#include <stdexcept>
#include <cstdint>
#include <vector>
#include <utility>
#include <iostream>
#include <string>
#include <fstream>
#include <algorithm>
#include <iterator>

using byte = std::uint8_t;
using bytes = std::vector<byte>;

/// Generate the keystream
///
/// I don't know exactly what this does, but to me this
/// essentially looks like a PRNG (probably non crypto-grade)
/// that takes the key as a seed.
///
/// Known properties:
/// * The key has to be made up of 256 unsigned bytes
/// * The PRNG generates chaotic values by indirectly
///   accessing key elements by taking another element as
///   index taking that as index again and doing some
///   summing
/// * It also generates chaos by swapping keys around in the
///   key (that's why we take a copy of the key)
/// * The resulting keystream is limited to bytes that also
///   occur in the key
/// * The keystreams symbol frequencies should be quite
///   similar to the keys
/// * I am pretty sure that the keystream leaks more
///   information about the key, but I haven't found out how
///   yet

class keystream_generator {
public:
	static constexpr std::size_t keysize = 256;

	keystream_generator(bytes key) : m_key{std::move(key)} {
		if (m_key.size() != keysize) {
			throw std::invalid_argument{"invalid keysize(" + std::to_string(key.size()) + ")"};
		}
	}

	byte operator()() {
		// variable meanings unknown

		// Values: 1, 2, 3, ..., 255, 1, ...Q
		byte h = static_cast<byte>((++m_i) % keysize);
		// Values: key[1], key[1] + key[2], ...
		// as subject to the swapping below
		m_q = (m_q + m_key[h]) % keysize;
		std::swap(m_key[h], m_key[m_q]);
		byte w = (m_key[h] + m_key[m_q]) % keysize;
		return m_key[w];
	}

	const bytes& key() const { return m_key; }
	std::size_t pos() const { return m_i; }

private:
	bytes m_key;
	std::size_t m_i = 0;
	byte m_q = 0;
};

class keystream_iterator : std::iterator<std::input_iterator_tag, const byte> {
public:
	keystream_iterator(bytes key) : m_gen{std::move(key)} {
		++(*this);
	}

	reference operator*() const { return m_current; }
	pointer operator->() const { return &m_current; }
	keystream_iterator& operator++() {
		m_current = m_gen();
		return *this;
	}
	struct byte_wrapper {
		byte value;
		byte operator*() const { return value; }
	};
	byte_wrapper operator++(int) {
		byte_wrapper retval{m_current};
		m_current = m_gen();
		return retval;
	}
	friend bool operator==(const keystream_iterator& l, const keystream_iterator& r) {
		return l.m_gen.key() == r.m_gen.key() and l.m_gen.pos() == r.m_gen.pos();
	}
	friend bool operator!=(const keystream_iterator& l, const keystream_iterator& r) {
		return !(l == r);
	}

private:
	keystream_generator m_gen;
	byte m_current;
};


bytes read_key(const std::string& filename) {
	constexpr auto keysize = keystream_generator::keysize;
	std::ifstream file{filename};
	if (!file.is_open()) {
		throw std::runtime_error{"could not open key-file"};
	}
	file >> std::noskipws;
	bytes key;
	key.reserve(keysize);
	std::copy_n(std::istream_iterator<byte>{file}, keysize, std::back_inserter(key));
	return key;
}


int usage(int retval) {
	std::cerr << "USAGE: "
	          << "\n  (1) terrible crypt keyfile <plaintext >cyphertext"
	          << "\n  (2) terrible keystream keyfile length > keystream_file"
	          << "\n  (3) terrible xor file_a file_b > result\n";
	return retval;
}


int main(int argc, char** argv) try {
	if (argc < 2) {
		return usage(1);
	}
	std::string command = argv[1];
	std::cin >> std::noskipws;
	std::ostream_iterator<byte> out{std::cout};

	if (command == "crypt") {
		std::istream_iterator<byte> in_it{std::cin};
		if (argc < 3) {
			return usage(1);
		}
		bytes key = read_key(argv[2]);
		std::transform(in_it, {}, keystream_iterator{key}, out, std::bit_xor<byte>{});
	} else if (command == "keystream") {
		if (argc < 4)
			return usage(1);
		bytes key = read_key(argv[2]);
		auto len = std::stoul(argv[3]);
		std::generate_n(out, len, keystream_generator{key});
	} else if (command == "xor") {
		if (argc < 4) {
			return usage(1);
		}
		std::fstream file_1{argv[2]};
		std::fstream file_2{argv[3]};
		if (!file_1.is_open() or !file_2.is_open()) {
			std::cerr << "Error: could not open file!\n";
			return 2;
		}
		file_1 >> std::noskipws;
		file_2 >> std::noskipws;
		using byte_it = std::istream_iterator<byte>;
		std::transform(byte_it{file_1}, {}, byte_it{file_2}, out, std::bit_xor<byte>{});
	} else {
		return usage(1);
	}
	return 0;
} catch(std::exception& e) {
	std::cerr << "Error: " << e.what() << '\n';
	return 3;
}
