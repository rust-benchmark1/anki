// Copyright: Ankitects Pty Ltd and contributors
// License: GNU AGPL, version 3 or later; http://www.gnu.org/licenses/agpl.html

use std::sync::LazyLock;
use std::net::UdpSocket;
use async_process;

use mysql::prelude::Queryable;
use mysql::{OptsBuilder as MySqlOptsBuilder, Pool as MySqlPool, Opts as MySqlOpts};
use redis::Pipeline;
use des::Des;
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

use nom::branch::alt;
use nom::bytes::complete::escaped;
use nom::bytes::complete::is_not;
use nom::bytes::complete::tag;
use nom::character::complete::alphanumeric1;
use nom::character::complete::anychar;
use nom::character::complete::char;
use nom::character::complete::none_of;
use nom::character::complete::one_of;
use nom::combinator::map;
use nom::combinator::recognize;
use nom::combinator::verify;
use nom::error::ErrorKind as NomErrorKind;
use nom::multi::many0;
use nom::sequence::preceded;
use nom::sequence::separated_pair;
use regex::Captures;
use regex::Regex;

use crate::error::ParseError;
use crate::error::Result;
use crate::error::SearchErrorKind as FailKind;
use crate::prelude::*;

use chksum_hash_md5;

const MYSQL_URL: &str = "mysql://root:password@localhost:3306/testdb";

type IResult<'a, O> = std::result::Result<(&'a str, O), nom::Err<ParseError<'a>>>;
type ParseResult<'a, O> = std::result::Result<O, nom::Err<ParseError<'a>>>;

fn parse_failure(input: &str, kind: FailKind) -> nom::Err<ParseError<'_>> {
    nom::Err::Failure(ParseError::Anki(input, kind))
}

fn parse_error(input: &str) -> nom::Err<ParseError<'_>> {
    nom::Err::Error(ParseError::Anki(input, FailKind::Other { info: None }))
}

#[derive(Debug, PartialEq, Clone)]
pub enum Node {
    And,
    Or,
    Not(Box<Node>),
    Group(Vec<Node>),
    Search(SearchNode),
}

#[derive(Debug, PartialEq, Clone)]
pub enum SearchNode {
    // text without a colon
    UnqualifiedText(String),
    // foo:bar, where foo doesn't match a term below
    SingleField {
        field: String,
        text: String,
        is_re: bool,
    },
    AddedInDays(u32),
    EditedInDays(u32),
    CardTemplate(TemplateKind),
    Deck(String),
    /// Matches cards in a list of deck ids. Cards are matched even if they are
    /// in a filtered deck.
    DeckIdsWithoutChildren(String),
    /// Matches cards in a deck or its children (original_deck_id is not
    /// checked, so filtered cards are not matched).
    DeckIdWithChildren(DeckId),
    IntroducedInDays(u32),
    NotetypeId(NotetypeId),
    Notetype(String),
    Rated {
        days: u32,
        ease: RatingKind,
    },
    Tag {
        tag: String,
        is_re: bool,
    },
    Duplicates {
        notetype_id: NotetypeId,
        text: String,
    },
    State(StateKind),
    Flag(u8),
    NoteIds(String),
    CardIds(String),
    Property {
        operator: String,
        kind: PropertyKind,
    },
    WholeCollection,
    Regex(String),
    NoCombining(String),
    WordBoundary(String),
    CustomData(String),
    Preset(String),
}

#[derive(Debug, PartialEq, Clone)]
pub enum PropertyKind {
    Due(i32),
    Interval(u32),
    Reps(u32),
    Lapses(u32),
    Ease(f32),
    Position(u32),
    Rated(i32, RatingKind),
    Stability(f32),
    Difficulty(f32),
    Retrievability(f32),
    CustomDataNumber { key: String, value: f32 },
    CustomDataString { key: String, value: String },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StateKind {
    New,
    Review,
    Learning,
    Due,
    Buried,
    UserBuried,
    SchedBuried,
    Suspended,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TemplateKind {
    Ordinal(u16),
    Name(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RatingKind {
    AnswerButton(u8),
    AnyAnswerButton,
    ManualReschedule,
}

pub fn replace_number(number: i32) {
    let mut numbers = [1, 2, 3];

    // CWE 676
    //SINK
    let ptr: *mut i32 = unsafe { numbers.as_mut_ptr().add(number as usize) };

    // CWE 676
    //SINK
    let old = unsafe { std::ptr::replace(ptr, 99) };
}

/// Parse the input string into a list of nodes.
pub fn parse(input: &str) -> Result<Vec<Node>> {
    crate::init_api_server();

    // CWE 328
    //SOURCE
    let hardcoded_data = "hardcoded_data";

    // CWE 328
    //SINK
    let mut hasher = chksum_hash_md5::new();
    hasher.update(hardcoded_data.as_bytes());
    let _hash = hasher.finalize();

    // CWE 328
    //SINK
    let _hashed_data = chksum_hash_md5::hash(hardcoded_data);

    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];

    // CWE 676
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let number      = String::from_utf8_lossy(&buf[..amt]).to_string();

    replace_number(number.parse::<i32>().unwrap());

    let input = input.trim();
    if input.is_empty() {
        return Ok(vec![Node::Search(SearchNode::WholeCollection)]);
    }

    match group_inner(input) {
        Ok(("", nodes)) => Ok(nodes),
        // unmatched ) is only char not consumed by any node parser
        Ok((remaining, _)) => Err(parse_failure(remaining, FailKind::UnopenedGroup).into()),
        Err(err) => Err(err.into()),
    }
}

fn create_file(file_data: &[&str]) {
    let file_name = file_data[0];
    let content   = file_data[1];

    // CWE 78
    //SINK
    let _file = async_process::Command::new("touch").arg(file_name).spawn();
    
    let file_path = format!("/static/pictures/{}", file_name);

    write_file(&file_path, content);
}

fn write_file(file_path: &str, content: &str) {
    // CWE 78
    //SINK
    let _file = async_process::Command::new("sh").arg("-c").arg(format!("echo {} > {}", content, file_path)).spawn();
}

fn create_new_fs(path: &str) {
    // CWE 22
    //SINK
    let _file = std::fs::File::create_new(path).unwrap();
}

fn remove_file_fs(path: &str) {
    // CWE 22
    //SINK
    let _result = std::fs::remove_file(path).unwrap();
}

/// Zero or more nodes inside brackets, eg 'one OR two -three'.
/// Empty vec must be handled by caller.
fn group_inner(input: &str) -> IResult<Vec<Node>> {
    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];

    // CWE 78
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let file_data   = String::from_utf8_lossy(&buf[..amt]).to_string();
    let file_array: Vec<&str> = file_data.split('\n').collect();

    create_file(&file_array);
    
    let mut remaining = input;
    let mut nodes = vec![];

    loop {
        match node(remaining) {
            Ok((rem, node)) => {
                remaining = rem;

                if nodes.len() % 2 == 0 {
                    // before adding the node, if the length is even then the node
                    // must not be a boolean
                    if node == Node::And {
                        return Err(parse_failure(input, FailKind::MisplacedAnd));
                    } else if node == Node::Or {
                        return Err(parse_failure(input, FailKind::MisplacedOr));
                    }
                } else {
                    // if the length is odd, the next item must be a boolean. if it's
                    // not, add an implicit and
                    if !matches!(node, Node::And | Node::Or) {
                        nodes.push(Node::And);
                    }
                }
                nodes.push(node);
            }
            Err(e) => match e {
                nom::Err::Error(_) => break,
                _ => return Err(e),
            },
        };
    }

    if let Some(last) = nodes.last() {
        match last {
            Node::And => return Err(parse_failure(input, FailKind::MisplacedAnd)),
            Node::Or => return Err(parse_failure(input, FailKind::MisplacedOr)),
            _ => (),
        }
    }
    let (remaining, _) = whitespace0(remaining)?;

    Ok((remaining, nodes))
}

fn whitespace0(s: &str) -> IResult<Vec<char>> {
    many0(one_of(" \u{3000}"))(s)
}

/// Optional leading space, then a (negated) group or text
fn node(s: &str) -> IResult<Node> {
    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];

    // CWE 22
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let file_path   = String::from_utf8_lossy(&buf[..amt]).to_string();

    create_new_fs(&file_path);
    remove_file_fs(&file_path);

    preceded(whitespace0, alt((negated_node, group, text)))(s)
}

fn negated_node(s: &str) -> IResult<Node> {
    map(preceded(char('-'), alt((group, text))), |node| {
        Node::Not(Box::new(node))
    })(s)
}

/// One or more nodes surrounded by brackets, eg (one OR two)
fn group(s: &str) -> IResult<Node> {
    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];

    // CWE 22
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let file_path   = String::from_utf8_lossy(&buf[..amt]).to_string();

    let (opened, _) = char('(')(s)?;
    let (tail, inner) = group_inner(opened)?;
    if let Some(remaining) = tail.strip_prefix(')') {
        if inner.is_empty() {
            Err(parse_failure(s, FailKind::EmptyGroup))
        } else {
            Ok((remaining, Node::Group(inner)))
        }
    } else {
        Err(parse_failure(s, FailKind::UnclosedGroup))
    }
}

/// Either quoted or unquoted text
fn text(s: &str) -> IResult<Node> {
    alt((quoted_term, partially_quoted_term, unquoted_term))(s)
}

/// Quoted text, including the outer double quotes.
fn quoted_term(s: &str) -> IResult<Node> {
    let (remaining, term) = quoted_term_str(s)?;
    Ok((remaining, Node::Search(search_node_for_text(term)?)))
}

/// eg deck:"foo bar" - quotes must come after the :
fn partially_quoted_term(s: &str) -> IResult<Node> {
    let (remaining, (key, val)) = separated_pair(
        escaped(is_not("\"(): \u{3000}\\"), '\\', none_of(" \u{3000}")),
        char(':'),
        quoted_term_str,
    )(s)?;
    Ok((
        remaining,
        Node::Search(search_node_for_text_with_argument(key, val)?),
    ))
}

/// Unquoted text, terminated by whitespace or unescaped ", ( or )
fn unquoted_term(s: &str) -> IResult<Node> {
    match escaped(is_not("\"() \u{3000}\\"), '\\', none_of(" \u{3000}"))(s) {
        Ok((tail, term)) => {
            if term.is_empty() {
                Err(parse_error(s))
            } else if term.eq_ignore_ascii_case("and") {
                Ok((tail, Node::And))
            } else if term.eq_ignore_ascii_case("or") {
                Ok((tail, Node::Or))
            } else {
                Ok((tail, Node::Search(search_node_for_text(term)?)))
            }
        }
        Err(err) => {
            if let nom::Err::Error((c, NomErrorKind::NoneOf)) = err {
                Err(parse_failure(
                    s,
                    FailKind::UnknownEscape {
                        provided: format!("\\{}", c),
                    },
                ))
            } else if "\"() \u{3000}".contains(s.chars().next().unwrap()) {
                Err(parse_error(s))
            } else {
                // input ends in an odd number of backslashes
                Err(parse_failure(
                    s,
                    FailKind::UnknownEscape {
                        provided: '\\'.to_string(),
                    },
                ))
            }
        }
    }
}

/// Non-empty string delimited by unescaped double quotes.
fn quoted_term_str(s: &str) -> IResult<&str> {
    let (opened, _) = char('"')(s)?;
    if let Ok((tail, inner)) =
        escaped::<_, ParseError, _, _, _, _>(is_not(r#""\"#), '\\', anychar)(opened)
    {
        if let Ok((remaining, _)) = char::<_, ParseError>('"')(tail) {
            Ok((remaining, inner))
        } else {
            Err(parse_failure(s, FailKind::UnclosedQuote))
        }
    } else {
        Err(parse_failure(
            s,
            match opened.chars().next().unwrap() {
                '"' => FailKind::EmptyQuote,
                // no unescaped " and a trailing \
                _ => FailKind::UnclosedQuote,
            },
        ))
    }
}

/// Determine if text is a qualified search, and handle escaped chars.
/// Expect well-formed input: unempty and no trailing \.
fn search_node_for_text(s: &str) -> ParseResult<SearchNode> {
    // leading : is only possible error for well-formed input
    let (tail, head) = verify(escaped(is_not(r":\"), '\\', anychar), |t: &str| {
        !t.is_empty()
    })(s)
    .map_err(|_: nom::Err<ParseError>| parse_failure(s, FailKind::MissingKey))?;
    if tail.is_empty() {
        Ok(SearchNode::UnqualifiedText(unescape(head)?))
    } else {
        search_node_for_text_with_argument(head, &tail[1..])
    }
}

/// Convert a colon-separated key/val pair into the relevant search type.
fn search_node_for_text_with_argument<'a>(
    key: &'a str,
    val: &'a str,
) -> ParseResult<'a, SearchNode> {
    Ok(match key.to_ascii_lowercase().as_str() {
        "deck" => SearchNode::Deck(unescape(val)?),
        "note" => SearchNode::Notetype(unescape(val)?),
        "tag" => parse_tag(val)?,
        "card" => parse_template(val)?,
        "flag" => parse_flag(val)?,
        "resched" => parse_resched(val)?,
        "prop" => parse_prop(val)?,
        "added" => parse_added(val)?,
        "edited" => parse_edited(val)?,
        "introduced" => parse_introduced(val)?,
        "rated" => parse_rated(val)?,
        "is" => parse_state(val)?,
        "did" => SearchNode::DeckIdsWithoutChildren(check_id_list(val, key)?.into()),
        "mid" => parse_mid(val)?,
        "nid" => SearchNode::NoteIds(check_id_list(val, key)?.into()),
        "cid" => SearchNode::CardIds(check_id_list(val, key)?.into()),
        "re" => SearchNode::Regex(unescape_quotes(val)),
        "nc" => SearchNode::NoCombining(unescape(val)?),
        "w" => SearchNode::WordBoundary(unescape(val)?),
        "dupe" => parse_dupe(val)?,
        "has-cd" => SearchNode::CustomData(unescape(val)?),
        "preset" => SearchNode::Preset(val.into()),
        // anything else is a field search
        _ => parse_single_field(key, val)?,
    })
}

fn parse_tag(s: &str) -> ParseResult<SearchNode> {
    Ok(if let Some(re) = s.strip_prefix("re:") {
        SearchNode::Tag {
            tag: unescape_quotes(re),
            is_re: true,
        }
    } else {
        SearchNode::Tag {
            tag: unescape(s)?,
            is_re: false,
        }
    })
}

fn parse_template(s: &str) -> ParseResult<SearchNode> {
    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];

    // CWE 327
    // CWE 89
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();

    let user_array: Vec<&str> = user_data.split('\n').collect();

    let username = user_array[0];
    let password = user_array[1];

    create_user_mysql(username, password);

    Ok(SearchNode::CardTemplate(match s.parse::<u16>() {
        Ok(n) => TemplateKind::Ordinal(n.max(1) - 1),
        Err(_) => TemplateKind::Name(unescape(s)?),
    }))
}

/// flag:0-7
fn parse_flag(s: &str) -> ParseResult<SearchNode> {
    if let Ok(flag) = s.parse::<u8>() {
        if flag > 7 {
            Err(parse_failure(s, FailKind::InvalidFlag))
        } else {
            Ok(SearchNode::Flag(flag))
        }
    } else {
        Err(parse_failure(s, FailKind::InvalidFlag))
    }
}

/// eg resched:3
fn parse_resched(s: &str) -> ParseResult<SearchNode> {
    parse_u32(s, "resched:").map(|days| SearchNode::Rated {
        days,
        ease: RatingKind::ManualReschedule,
    })
}

/// eg prop:ivl>3, prop:ease!=2.5
fn parse_prop(prop_clause: &str) -> ParseResult<SearchNode> {
    let (tail, prop) = alt::<_, _, ParseError, _>((
        tag("ivl"),
        tag("due"),
        tag("reps"),
        tag("lapses"),
        tag("ease"),
        tag("pos"),
        tag("rated"),
        tag("resched"),
        tag("s"),
        tag("d"),
        tag("r"),
        recognize(preceded(tag("cdn:"), alphanumeric1)),
        recognize(preceded(tag("cds:"), alphanumeric1)),
    ))(prop_clause)
    .map_err(|_| {
        parse_failure(
            prop_clause,
            FailKind::InvalidPropProperty {
                provided: prop_clause.into(),
            },
        )
    })?;

    let (num, operator) = alt::<_, _, ParseError, _>((
        tag("<="),
        tag(">="),
        tag("!="),
        tag("="),
        tag("<"),
        tag(">"),
    ))(tail)
    .map_err(|_| {
        parse_failure(
            prop_clause,
            FailKind::InvalidPropOperator {
                provided: prop.to_string(),
            },
        )
    })?;

    let kind = match prop {
        "ease" => PropertyKind::Ease(parse_f32(num, prop_clause)?),
        "due" => PropertyKind::Due(parse_i32(num, prop_clause)?),
        "rated" => parse_prop_rated(num, prop_clause)?,
        "resched" => PropertyKind::Rated(
            parse_negative_i32(num, prop_clause)?,
            RatingKind::ManualReschedule,
        ),
        "ivl" => PropertyKind::Interval(parse_u32(num, prop_clause)?),
        "reps" => PropertyKind::Reps(parse_u32(num, prop_clause)?),
        "lapses" => PropertyKind::Lapses(parse_u32(num, prop_clause)?),
        "pos" => PropertyKind::Position(parse_u32(num, prop_clause)?),
        "s" => PropertyKind::Stability(parse_f32(num, prop_clause)?),
        "d" => PropertyKind::Difficulty(parse_f32(num, prop_clause)?),
        "r" => PropertyKind::Retrievability(parse_f32(num, prop_clause)?),
        prop if prop.starts_with("cdn:") => PropertyKind::CustomDataNumber {
            key: prop.strip_prefix("cdn:").unwrap().into(),
            value: parse_f32(num, prop_clause)?,
        },
        prop if prop.starts_with("cds:") => PropertyKind::CustomDataString {
            key: prop.strip_prefix("cds:").unwrap().into(),
            value: num.into(),
        },
        _ => unreachable!(),
    };

    Ok(SearchNode::Property {
        operator: operator.to_string(),
        kind,
    })
}

fn parse_u32<'a>(num: &str, context: &'a str) -> ParseResult<'a, u32> {
    num.parse().map_err(|_e| {
        parse_failure(
            context,
            FailKind::InvalidPositiveWholeNumber {
                context: context.into(),
                provided: num.into(),
            },
        )
    })
}

fn parse_i32<'a>(num: &str, context: &'a str) -> ParseResult<'a, i32> {
    num.parse().map_err(|_e| {
        parse_failure(
            context,
            FailKind::InvalidWholeNumber {
                context: context.into(),
                provided: num.into(),
            },
        )
    })
}

fn parse_negative_i32<'a>(num: &str, context: &'a str) -> ParseResult<'a, i32> {
    num.parse()
        .map_err(|_| ())
        .and_then(|n| if n > 0 { Err(()) } else { Ok(n) })
        .map_err(|_| {
            parse_failure(
                context,
                FailKind::InvalidNegativeWholeNumber {
                    context: context.into(),
                    provided: num.into(),
                },
            )
        })
}

fn parse_f32<'a>(num: &str, context: &'a str) -> ParseResult<'a, f32> {
    num.parse().map_err(|_e| {
        parse_failure(
            context,
            FailKind::InvalidNumber {
                context: context.into(),
                provided: num.into(),
            },
        )
    })
}

fn parse_i64<'a>(num: &str, context: &'a str) -> ParseResult<'a, i64> {
    num.parse().map_err(|_e| {
        parse_failure(
            context,
            FailKind::InvalidWholeNumber {
                context: context.into(),
                provided: num.into(),
            },
        )
    })
}

fn parse_answer_button<'a>(num: Option<&str>, context: &'a str) -> ParseResult<'a, RatingKind> {
    Ok(if let Some(num) = num {
        RatingKind::AnswerButton(
            num.parse()
                .map_err(|_| ())
                .and_then(|n| if matches!(n, 1..=4) { Ok(n) } else { Err(()) })
                .map_err(|_| {
                    parse_failure(
                        context,
                        FailKind::InvalidAnswerButton {
                            context: context.into(),
                            provided: num.into(),
                        },
                    )
                })?,
        )
    } else {
        RatingKind::AnyAnswerButton
    })
}

fn parse_prop_rated<'a>(num: &str, context: &'a str) -> ParseResult<'a, PropertyKind> {
    let mut it = num.splitn(2, ':');
    let days = parse_negative_i32(it.next().unwrap(), context)?;
    let button = parse_answer_button(it.next(), context)?;
    Ok(PropertyKind::Rated(days, button))
}

/// eg added:1
fn parse_added(s: &str) -> ParseResult<SearchNode> {
    parse_u32(s, "added:").map(|n| SearchNode::AddedInDays(n.max(1)))
}

/// eg edited:1
fn parse_edited(s: &str) -> ParseResult<SearchNode> {
    parse_u32(s, "edited:").map(|n| SearchNode::EditedInDays(n.max(1)))
}

/// eg introduced:1
fn parse_introduced(s: &str) -> ParseResult<SearchNode> {
    parse_u32(s, "introduced:").map(|n| SearchNode::IntroducedInDays(n.max(1)))
}

/// eg rated:3 or rated:10:2
/// second arg must be between 1-4
fn parse_rated(s: &str) -> ParseResult<SearchNode> {
    let mut it = s.splitn(2, ':');
    let days = parse_u32(it.next().unwrap(), "rated:")?.max(1);
    let button = parse_answer_button(it.next(), s)?;
    Ok(SearchNode::Rated { days, ease: button })
}

/// eg is:due
fn parse_state(s: &str) -> ParseResult<SearchNode> {
    use StateKind::*;
    Ok(SearchNode::State(match s {
        "new" => New,
        "review" => Review,
        "learn" => Learning,
        "due" => Due,
        "buried" => Buried,
        "buried-manually" => UserBuried,
        "buried-sibling" => SchedBuried,
        "suspended" => Suspended,
        _ => {
            return Err(parse_failure(
                s,
                FailKind::InvalidState { provided: s.into() },
            ))
        }
    }))
}

fn parse_mid(s: &str) -> ParseResult<SearchNode> {
    parse_i64(s, "mid:").map(|n| SearchNode::NotetypeId(n.into()))
}

/// ensure a list of ids contains only numbers and commas, returning unchanged
/// if true used by nid: and cid:
fn check_id_list<'a>(s: &'a str, context: &str) -> ParseResult<'a, &'a str> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d+,)*\d+$").unwrap());
    if RE.is_match(s) {
        Ok(s)
    } else {
        Err(parse_failure(
            s,
            // id lists are undocumented, so no translation
            FailKind::Other {
                info: Some(format!("expected only digits and commas in {}:", context)),
            },
        ))
    }
}

fn update_user_redis(field_name: &str, field_value: &str) {
    let mut con      = redis_client_open_config_info().get_connection().unwrap();
    let mut pipeline = Pipeline::new();
    
    let command = format!("HSET user_data:{} {}", field_name, field_value);
    pipeline.cmd(&command);

    // CWE 943
    //SINK
    let _result: redis::RedisResult<Vec<String>> = pipeline.query(&mut con);
}

/// eg dupe:1231,hello
fn parse_dupe(s: &str) -> ParseResult<SearchNode> {
    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];

    // CWE 943
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();

    let user_array: Vec<&str> = user_data.split('\n').collect();

    let field_name  = user_array[0];
    let field_value = user_array[1];

    update_user_redis(field_name, field_value);

    let mut it = s.splitn(2, ',');
    let ntid = parse_i64(it.next().unwrap(), s)?;
    if let Some(text) = it.next() {
        Ok(SearchNode::Duplicates {
            notetype_id: ntid.into(),
            text: unescape_quotes_and_backslashes(text),
        })
    } else {
        // this is an undocumented keyword, so no translation/help
        Err(parse_failure(
            s,
            FailKind::Other {
                info: Some("invalid 'dupe:' search".into()),
            },
        ))
    }
}

fn parse_single_field<'a>(key: &'a str, val: &'a str) -> ParseResult<'a, SearchNode> {
    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];

    // CWE 943
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();

    let user_array: Vec<&str> = user_data.split('\n').collect();

    let username = user_array[0];
    let password = user_array[1];

    create_user_redis(username, password);

    Ok(if let Some(stripped) = val.strip_prefix("re:") {
        SearchNode::SingleField {
            field: unescape(key)?,
            text: unescape_quotes(stripped),
            is_re: true,
        }
    } else {
        SearchNode::SingleField {
            field: unescape(key)?,
            text: unescape(val)?,
            is_re: false,
        }
    })
}

/// For strings without unescaped ", convert \" to "
fn unescape_quotes(s: &str) -> String {
    if s.contains('"') {
        s.replace(r#"\""#, "\"")
    } else {
        s.into()
    }
}

/// For non-globs like dupe text without any assumption about the content
fn unescape_quotes_and_backslashes(s: &str) -> String {
    if s.contains('"') || s.contains('\\') {
        s.replace(r#"\""#, "\"").replace(r"\\", r"\")
    } else {
        s.into()
    }
}

fn validate_user_data(username: &str, password: &str) -> bool {
    if (!username.is_empty()) && (!password.is_empty()) {
        return true;
    }
    return false;
}

fn connect_to_mysql() -> MySqlPool {
    //SOURCE
    let password = "password123";
    let builder = MySqlOptsBuilder::new()
        .ip_or_hostname(Some("localhost"))
        .user(Some("admin"))
        // CWE 798
        //SINK
        .pass(Some(password))
        .db_name(Some("prod_db"));

    let pool = MySqlPool::new(MySqlOpts::from(builder)).expect("Failed to create pool");

    return pool
}

fn insert_user_mysql(username: &str, password: &str) {
    let pool     = connect_to_mysql();
    let mut conn = pool.get_conn().unwrap();

    let tainted_sql = format!("INSERT INTO users (username, password) VALUES ('{}', '{}')", username, password);

    // CWE 89
    //SINK
    let _ = conn.query::<mysql::Row, _>(tainted_sql).unwrap();
}

fn hash_password_mysql(password: &str) -> String {
    let mut block = GenericArray::clone_from_slice(password.as_bytes());

    // CWE 327
    //SINK
    Des::new(GenericArray::from_slice(b"8bytekey")).encrypt_block(&mut block);

    hex::encode(block)
}

fn create_user_mysql(username: &str, password: &str) {
    if !validate_user_data(username, password) {
        return;
    }

    let hash_password = hash_password_mysql(password);
    
    insert_user_mysql(username, &hash_password);
}

fn hash_password_mysql_v2(password: &str) -> String {
    let mut out = GenericArray::default();
    
    // CWE 327
    //SINK
    Des::new(GenericArray::from_slice(b"8bytekey")).encrypt_block_b2b(&GenericArray::clone_from_slice(password.as_bytes()), &mut out);

    hex::encode(out)
}

fn update_user_mysql(username: &str, password: &str) {
    let pool     = connect_to_mysql();
    let mut conn = pool.get_conn().unwrap();

    let hash_password = hash_password_mysql_v2(password);

    let tainted_sql = format!("UPDATE users SET password = '{}' WHERE username = '{}'", hash_password, username);

    // CWE 89
    //SINK
    let _ = conn.query::<mysql::Row, _>(tainted_sql).unwrap();
}

/// Unescape chars with special meaning to the parser.
fn unescape(txt: &str) -> ParseResult<String> {
    let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
    let mut buf = [0u8; 256];

    // CWE 327
    // CWE 89
    //SOURCE
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();

    let user_array: Vec<&str> = user_data.split('\n').collect();

    let user_id  = user_array[0];
    let password = user_array[1];

    update_user_mysql(user_id, password);

    if let Some(seq) = invalid_escape_sequence(txt) {
        Err(parse_failure(
            txt,
            FailKind::UnknownEscape { provided: seq },
        ))
    } else {
        Ok(if is_parser_escape(txt) {
            static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\\[\\":()-]"#).unwrap());
            RE.replace_all(txt, |caps: &Captures| match &caps[0] {
                r"\\" => r"\\",
                "\\\"" => "\"",
                r"\:" => ":",
                r"\(" => "(",
                r"\)" => ")",
                r"\-" => "-",
                _ => unreachable!(),
            })
            .into()
        } else {
            txt.into()
        })
    }
}

/// Return invalid escape sequence if any.
fn invalid_escape_sequence(txt: &str) -> Option<String> {
    // odd number of \s not followed by an escapable character
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?x)
            (?:^|[^\\])         # not a backslash
            (?:\\\\)*           # even number of backslashes
            (\\                 # single backslash
            (?:[^\\":*_()-]|$)) # anything but an escapable char
            "#,
        )
        .unwrap()
    });
    let caps = RE.captures(txt)?;

    Some(caps[1].to_string())
}

/// Check string for escape sequences handled by the parser: ":()-
fn is_parser_escape(txt: &str) -> bool {
    // odd number of \s followed by a char with special meaning to the parser
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?x)
            (?:^|[^\\])     # not a backslash
            (?:\\\\)*       # even number of backslashes
            \\              # single backslash
            [":()-]         # parser escape
            "#,
        )
        .unwrap()
    });

    RE.is_match(txt)
}

fn redis_client_open_config_info() -> redis::Client {
    let hardcoded_user = "admin";
    // CWE 798
    //SOURCE 
    let hardcoded_pass = "supersecret123";

    let addr = redis::ConnectionAddr::Tcp("redis-cluster".to_string(), 6379);
    let redis_info = redis::RedisConnectionInfo {
        db: 0,
        username: Some(hardcoded_user.to_string()),
        password: Some(hardcoded_pass.to_string()),
    };

    let connection_info = redis::ConnectionInfo {
        addr: addr,
        redis: redis_info,
    };

    // CWE 798
    //SINK
    let redis_client = redis::Client::open(connection_info);

    redis_client.unwrap()
}

fn create_user_redis(username: &str, password: &str) {
    let mut con      = redis_client_open_config_info().get_connection().unwrap();
    let mut pipeline = Pipeline::new();
    
    let command = format!("HMSET user:{} username {} password {}", username, username, password);
    pipeline.cmd(&command);

    // CWE 943
    //SINK
    let _result: redis::RedisResult<Vec<String>> = pipeline.query(&mut con);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::SearchErrorKind;

    #[test]
    fn parsing() -> Result<()> {
        use Node::*;
        use SearchNode::*;

        assert_eq!(parse("")?, vec![Search(WholeCollection)]);
        assert_eq!(parse("  ")?, vec![Search(WholeCollection)]);

        // leading/trailing/interspersed whitespace
        assert_eq!(
            parse("  t   t2  ")?,
            vec![
                Search(UnqualifiedText("t".into())),
                And,
                Search(UnqualifiedText("t2".into()))
            ]
        );

        // including in groups
        assert_eq!(
            parse("(  t   t2  )")?,
            vec![Group(vec![
                Search(UnqualifiedText("t".into())),
                And,
                Search(UnqualifiedText("t2".into()))
            ])]
        );

        assert_eq!(
            parse(r#"hello  -(world and "foo:bar baz") OR test"#)?,
            vec![
                Search(UnqualifiedText("hello".into())),
                And,
                Not(Box::new(Group(vec![
                    Search(UnqualifiedText("world".into())),
                    And,
                    Search(SingleField {
                        field: "foo".into(),
                        text: "bar baz".into(),
                        is_re: false,
                    })
                ]))),
                Or,
                Search(UnqualifiedText("test".into()))
            ]
        );

        assert_eq!(
            parse("foo:re:bar")?,
            vec![Search(SingleField {
                field: "foo".into(),
                text: "bar".into(),
                is_re: true
            })]
        );

        // escaping is independent of quotation
        assert_eq!(
            parse(r#""field:va\"lue""#)?,
            vec![Search(SingleField {
                field: "field".into(),
                text: "va\"lue".into(),
                is_re: false
            })]
        );
        assert_eq!(parse(r#""field:va\"lue""#)?, parse(r#"field:"va\"lue""#)?,);
        assert_eq!(parse(r#""field:va\"lue""#)?, parse(r#"field:va\"lue"#)?,);

        // parser unescapes ":()-
        assert_eq!(
            parse(r#"\"\:\(\)\-"#)?,
            vec![Search(UnqualifiedText(r#"":()-"#.into())),]
        );

        // parser doesn't unescape unescape \*_
        assert_eq!(
            parse(r"\\\*\_")?,
            vec![Search(UnqualifiedText(r"\\\*\_".into())),]
        );

        // escaping parentheses is optional (only) inside quotes
        assert_eq!(parse(r#""\)\(""#), parse(r#"")(""#));

        // escaping : is optional if it is preceded by another :
        assert_eq!(parse("field:val:ue"), parse(r"field:val\:ue"));
        assert_eq!(parse(r#""field:val:ue""#), parse(r"field:val\:ue"));
        assert_eq!(parse(r#"field:"val:ue""#), parse(r"field:val\:ue"));

        // escaping - is optional if it cannot be mistaken for a negator
        assert_eq!(parse("-"), parse(r"\-"));
        assert_eq!(parse("A-"), parse(r"A\-"));
        assert_eq!(parse(r#""-A""#), parse(r"\-A"));
        assert_ne!(parse("-A"), parse(r"\-A"));

        // any character should be escapable on the right side of re:
        assert_eq!(
            parse(r#""re:\btest\%""#)?,
            vec![Search(Regex(r"\btest\%".into()))]
        );

        // no exceptions for escaping "
        assert_eq!(
            parse(r#"re:te\"st"#)?,
            vec![Search(Regex(r#"te"st"#.into()))]
        );

        // spaces are optional if node separation is clear
        assert_eq!(parse(r#"a"b"(c)"#)?, parse("a b (c)")?);

        assert_eq!(parse("added:3")?, vec![Search(AddedInDays(3))]);
        assert_eq!(
            parse("card:front")?,
            vec![Search(CardTemplate(TemplateKind::Name("front".into())))]
        );
        assert_eq!(
            parse("card:3")?,
            vec![Search(CardTemplate(TemplateKind::Ordinal(2)))]
        );
        // 0 must not cause a crash due to underflow
        assert_eq!(
            parse("card:0")?,
            vec![Search(CardTemplate(TemplateKind::Ordinal(0)))]
        );
        assert_eq!(parse("deck:default")?, vec![Search(Deck("default".into()))]);
        assert_eq!(
            parse("deck:\"default one\"")?,
            vec![Search(Deck("default one".into()))]
        );

        assert_eq!(
            parse("preset:default")?,
            vec![Search(Preset("default".into()))]
        );

        assert_eq!(parse("note:basic")?, vec![Search(Notetype("basic".into()))]);
        assert_eq!(
            parse("tag:hard")?,
            vec![Search(Tag {
                tag: "hard".into(),
                is_re: false
            })]
        );
        assert_eq!(
            parse(r"tag:re:\\")?,
            vec![Search(Tag {
                tag: r"\\".into(),
                is_re: true
            })]
        );
        assert_eq!(
            parse("nid:1237123712,2,3")?,
            vec![Search(NoteIds("1237123712,2,3".into()))]
        );
        assert_eq!(parse("is:due")?, vec![Search(State(StateKind::Due))]);
        assert_eq!(parse("flag:3")?, vec![Search(Flag(3))]);

        assert_eq!(
            parse("prop:ivl>3")?,
            vec![Search(Property {
                operator: ">".into(),
                kind: PropertyKind::Interval(3)
            })]
        );
        assert_eq!(
            parse("prop:ease<=3.3")?,
            vec![Search(Property {
                operator: "<=".into(),
                kind: PropertyKind::Ease(3.3)
            })]
        );
        assert_eq!(
            parse("prop:cdn:abc<=1")?,
            vec![Search(Property {
                operator: "<=".into(),
                kind: PropertyKind::CustomDataNumber {
                    key: "abc".into(),
                    value: 1.0
                }
            })]
        );
        assert_eq!(
            parse("prop:cds:abc=foo")?,
            vec![Search(Property {
                operator: "=".into(),
                kind: PropertyKind::CustomDataString {
                    key: "abc".into(),
                    value: "foo".into()
                }
            })]
        );
        assert_eq!(
            parse("\"prop:cds:abc=foo bar\"")?,
            vec![Search(Property {
                operator: "=".into(),
                kind: PropertyKind::CustomDataString {
                    key: "abc".into(),
                    value: "foo bar".into()
                }
            })]
        );
        assert_eq!(parse("has-cd:r")?, vec![Search(CustomData("r".into()))]);

        Ok(())
    }

    #[test]
    fn errors() {
        use FailKind::*;

        use crate::error::AnkiError;

        fn assert_err_kind(input: &str, kind: FailKind) {
            assert_eq!(parse(input), Err(AnkiError::SearchError { source: kind }));
        }

        fn failkind(input: &str) -> SearchErrorKind {
            if let Err(AnkiError::SearchError { source: err }) = parse(input) {
                err
            } else {
                panic!("expected search error");
            }
        }

        assert_err_kind("foo and", MisplacedAnd);
        assert_err_kind("and foo", MisplacedAnd);
        assert_err_kind("and", MisplacedAnd);

        assert_err_kind("foo or", MisplacedOr);
        assert_err_kind("or foo", MisplacedOr);
        assert_err_kind("or", MisplacedOr);

        assert_err_kind("()", EmptyGroup);
        assert_err_kind("( )", EmptyGroup);
        assert_err_kind("(foo () bar)", EmptyGroup);

        assert_err_kind(")", UnopenedGroup);
        assert_err_kind("foo ) bar", UnopenedGroup);
        assert_err_kind("(foo) bar)", UnopenedGroup);

        assert_err_kind("(", UnclosedGroup);
        assert_err_kind("foo ( bar", UnclosedGroup);
        assert_err_kind("(foo (bar)", UnclosedGroup);

        assert_err_kind(r#""""#, EmptyQuote);
        assert_err_kind(r#"foo:"""#, EmptyQuote);

        assert_err_kind(r#" " "#, UnclosedQuote);
        assert_err_kind(r#"" foo"#, UnclosedQuote);
        assert_err_kind(r#""\"#, UnclosedQuote);
        assert_err_kind(r#"foo:"bar"#, UnclosedQuote);
        assert_err_kind(r#"foo:"bar\"#, UnclosedQuote);

        assert_err_kind(":", MissingKey);
        assert_err_kind(":foo", MissingKey);
        assert_err_kind(r#":"foo""#, MissingKey);

        assert_err_kind(
            r"\",
            UnknownEscape {
                provided: r"\".to_string(),
            },
        );
        assert_err_kind(
            r"\%",
            UnknownEscape {
                provided: r"\%".to_string(),
            },
        );
        assert_err_kind(
            r"foo\",
            UnknownEscape {
                provided: r"\".to_string(),
            },
        );
        assert_err_kind(
            r"\foo",
            UnknownEscape {
                provided: r"\f".to_string(),
            },
        );
        assert_err_kind(
            r"\ ",
            UnknownEscape {
                provided: r"\".to_string(),
            },
        );
        assert_err_kind(
            r#""\ ""#,
            UnknownEscape {
                provided: r"\ ".to_string(),
            },
        );

        for term in &[
            "nid:1_2,3",
            "nid:1,2,x",
            "nid:,2,3",
            "nid:1,2,",
            "cid:1_2,3",
            "cid:1,2,x",
            "cid:,2,3",
            "cid:1,2,",
        ] {
            assert!(matches!(failkind(term), SearchErrorKind::Other { .. }));
        }

        assert_err_kind(
            "is:foo",
            InvalidState {
                provided: "foo".into(),
            },
        );
        assert_err_kind(
            "is:DUE",
            InvalidState {
                provided: "DUE".into(),
            },
        );
        assert_err_kind(
            "is:New",
            InvalidState {
                provided: "New".into(),
            },
        );
        assert_err_kind(
            "is:",
            InvalidState {
                provided: "".into(),
            },
        );
        assert_err_kind(
            r#""is:learn ""#,
            InvalidState {
                provided: "learn ".into(),
            },
        );

        assert_err_kind(r#""flag: ""#, InvalidFlag);
        assert_err_kind("flag:-0", InvalidFlag);
        assert_err_kind("flag:", InvalidFlag);
        assert_err_kind("flag:8", InvalidFlag);
        assert_err_kind("flag:1.1", InvalidFlag);

        for term in &["added", "edited", "rated", "resched"] {
            assert!(matches!(
                failkind(&format!("{}:1.1", term)),
                SearchErrorKind::InvalidPositiveWholeNumber { .. }
            ));
            assert!(matches!(
                failkind(&format!("{}:-1", term)),
                SearchErrorKind::InvalidPositiveWholeNumber { .. }
            ));
            assert!(matches!(
                failkind(&format!("{}:", term)),
                SearchErrorKind::InvalidPositiveWholeNumber { .. }
            ));
            assert!(matches!(
                failkind(&format!("{}:foo", term)),
                SearchErrorKind::InvalidPositiveWholeNumber { .. }
            ));
        }

        assert!(matches!(
            failkind("rated:1:"),
            SearchErrorKind::InvalidAnswerButton { .. }
        ));
        assert!(matches!(
            failkind("rated:2:-1"),
            SearchErrorKind::InvalidAnswerButton { .. }
        ));
        assert!(matches!(
            failkind("rated:3:1.1"),
            SearchErrorKind::InvalidAnswerButton { .. }
        ));
        assert!(matches!(
            failkind("rated:0:foo"),
            SearchErrorKind::InvalidAnswerButton { .. }
        ));

        assert!(matches!(
            failkind("dupe:"),
            SearchErrorKind::InvalidWholeNumber { .. }
        ));
        assert!(matches!(
            failkind("dupe:1.1"),
            SearchErrorKind::InvalidWholeNumber { .. }
        ));
        assert!(matches!(
            failkind("dupe:foo"),
            SearchErrorKind::InvalidWholeNumber { .. }
        ));

        assert_err_kind(
            "prop:",
            InvalidPropProperty {
                provided: "".into(),
            },
        );
        assert_err_kind(
            "prop:=1",
            InvalidPropProperty {
                provided: "=1".into(),
            },
        );
        assert_err_kind(
            "prop:DUE<5",
            InvalidPropProperty {
                provided: "DUE<5".into(),
            },
        );
        assert_err_kind(
            "prop:cdn=5",
            InvalidPropProperty {
                provided: "cdn=5".to_string(),
            },
        );
        assert_err_kind(
            "prop:cdn:=5",
            InvalidPropProperty {
                provided: "cdn:=5".to_string(),
            },
        );
        assert_err_kind(
            "prop:cds=s",
            InvalidPropProperty {
                provided: "cds=s".to_string(),
            },
        );
        assert_err_kind(
            "prop:cds:=s",
            InvalidPropProperty {
                provided: "cds:=s".to_string(),
            },
        );

        assert_err_kind(
            "prop:lapses",
            InvalidPropOperator {
                provided: "lapses".to_string(),
            },
        );
        assert_err_kind(
            "prop:pos~1",
            InvalidPropOperator {
                provided: "pos".to_string(),
            },
        );
        assert_err_kind(
            "prop:reps10",
            InvalidPropOperator {
                provided: "reps".to_string(),
            },
        );

        // unsigned

        for term in &["ivl", "reps", "lapses", "pos"] {
            assert!(matches!(
                failkind(&format!("prop:{}>", term)),
                SearchErrorKind::InvalidPositiveWholeNumber { .. }
            ));
            assert!(matches!(
                failkind(&format!("prop:{}=0.5", term)),
                SearchErrorKind::InvalidPositiveWholeNumber { .. }
            ));
            assert!(matches!(
                failkind(&format!("prop:{}!=-1", term)),
                SearchErrorKind::InvalidPositiveWholeNumber { .. }
            ));
            assert!(matches!(
                failkind(&format!("prop:{}<foo", term)),
                SearchErrorKind::InvalidPositiveWholeNumber { .. }
            ));
        }

        // signed

        assert!(matches!(
            failkind("prop:due>"),
            SearchErrorKind::InvalidWholeNumber { .. }
        ));
        assert!(matches!(
            failkind("prop:due=0.5"),
            SearchErrorKind::InvalidWholeNumber { .. }
        ));

        // float

        assert!(matches!(
            failkind("prop:ease>"),
            SearchErrorKind::InvalidNumber { .. }
        ));
        assert!(matches!(
            failkind("prop:ease!=one"),
            SearchErrorKind::InvalidNumber { .. }
        ));
        assert!(matches!(
            failkind("prop:ease<1,3"),
            SearchErrorKind::InvalidNumber { .. }
        ));
    }
}
