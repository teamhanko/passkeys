import { Result$Ok, Result$Error, List$Empty, List$NonEmpty } from "../../gleam.mjs";
import {
  GleamPanic$GleamPanic,
  PanicKind$Todo,
  PanicKind$Panic,
  PanicKind$LetAssert,
  PanicKind$Assert,
  AssertKind$BinaryOperator,
  AssertKind$FunctionCall,
  AssertKind$OtherExpression,
  AssertedExpression$AssertedExpression,
  ExpressionKind$Literal,
  ExpressionKind$Expression,
  ExpressionKind$Unevaluated,
} from "./gleam_panic.mjs";

export function from_dynamic(error) {
  if (!(error instanceof globalThis.Error) || !error.gleam_error) {
    return Result$Error(undefined);
  }

  if (error.gleam_error === "todo") {
    return wrap(error, PanicKind$Todo());
  }

  if (error.gleam_error === "panic") {
    return wrap(error, PanicKind$Panic());
  }

  if (error.gleam_error === "let_assert") {
    let kind = PanicKind$LetAssert(
      error.start,
      error.end,
      error.pattern_start,
      error.pattern_end,
      error.value,
    );
    return wrap(error, kind);
  }

  if (error.gleam_error === "assert") {
    let kind = PanicKind$Assert(
      error.start,
      error.end,
      error.expression_start,
      assert_kind(error),
    );
    return wrap(error, kind);
  }

  return Result$Error(undefined);
}

function assert_kind(error) {
  if (error.kind == "binary_operator") {
    return AssertKind$BinaryOperator(
      error.operator,
      expression(error.left),
      expression(error.right),
    );
  }

  if (error.kind == "function_call") {
    let list = List$Empty();
    let i = error.arguments.length;
    while (i--) {
      list = List$NonEmpty(expression(error.arguments[i]), list);
    }
    return AssertKind$FunctionCall(list);
  }

  return AssertKind$OtherExpression(expression(error.expression));
}

function expression(data) {
  const expression = AssertedExpression$AssertedExpression(data.start, data.end, undefined);
  if (data.kind == "literal") {
    expression.kind = ExpressionKind$Literal(data.value);
  } else if (data.kind == "expression") {
    expression.kind = ExpressionKind$Expression(data.value);
  } else {
    expression.kind = ExpressionKind$Unevaluated();
  }
  return expression;
}

function wrap(e, kind) {
  return Result$Ok(
    GleamPanic$GleamPanic(e.message, e.file, e.module, e.function, e.line, kind),
  );
}
