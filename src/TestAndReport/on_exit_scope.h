#pragma once
#include <utility>

//#include <gsl/gsl_util>
#ifndef GSL_UTIL_H
namespace gsl
{
	// final_action allows you to ensure something gets run at the end of a scope
	template <class F> class final_action
	{
	public:
		explicit final_action(F f) noexcept : f_(std::move(f)) {}

		final_action(final_action &&other) noexcept
			: f_(std::move(other.f_)), invoke_(other.invoke_)
		{
			other.invoke_ = false;
		}

		final_action(const final_action &) = delete;
		final_action &operator=(const final_action &) = delete;

		~final_action() noexcept
		{
			if (invoke_)
				f_();
		}

	private:
		F f_;
		bool invoke_{ true };
	};

	// finally() - convenience function to generate a final_action
	template <class F> final_action<F> finally(const F &f) noexcept
	{
		return final_action<F>(f);
	}

	template <class F> final_action<F> finally(F &&f) noexcept
	{
		return final_action<F>(std::forward<F>(f));
	}
} // namespace gsl
#endif //! GSL_UTIL_H

#ifndef MACRO_CONCAT
#define MACRO_CONCAT_IMPL(x, y) x##y
#define MACRO_CONCAT(x, y) MACRO_CONCAT_IMPL(x, y)
#endif

#define ON_EXIT_SCOPE(...)                                                     \
  const auto MACRO_CONCAT(__final_act_, __COUNTER__) =                         \
      gsl::finally([&] { __VA_ARGS__; });
